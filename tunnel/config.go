package tunnel

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Lafeng/deblocus/auth"
	"github.com/Lafeng/deblocus/exception"
	"github.com/kardianos/osext"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	SER_KEY_TYPE         = "deblocus/SERVER-PRIVATEKEY"
	USER_CREDENTIAL_TYPE = "deblocus/CLIENT-CREDENTIAL"
	WORD_d5p             = "D5P"
	WORD_provider        = "Provider"
	SIZE_UNIT            = "BKMG"
)

var (
	FILE_NOT_FOUND          = exception.NewW("File not found")
	FILE_EXISTS             = exception.NewW("File is already exists")
	INVALID_D5P_FRAGMENT    = exception.NewW("Invalid d5p fragment")
	INVALID_D5C_FILE        = exception.NewW("Invalid d5c file format")
	INVALID_D5S_FILE        = exception.NewW("Invalid d5s file format")
	UNRECOGNIZED_SYMBOLS    = exception.NewW("Unrecognized symbols")
	UNRECOGNIZED_DIRECTIVES = exception.NewW("Unrecognized directives")
	LOCAL_BIND_ERROR        = exception.NewW("Local bind error")
	CONF_MISS               = exception.NewW("Missed config")
	CONF_ERROR              = exception.NewW("Error config")
)

// client
type D5ClientConf struct {
	Listen     string `importable:":9009"`
	Verbose    int    `importable:"1"`
	ListenAddr *net.TCPAddr
	D5PList    []*D5Params
}

func (c *D5ClientConf) validate() error {
	if len(c.D5PList) < 1 {
		return CONF_MISS.Apply("Not found d5p fragment")
	}
	if c.Listen == "" {
		return LOCAL_BIND_ERROR
	}
	a, e := net.ResolveTCPAddr("tcp", c.Listen)
	if e != nil {
		return LOCAL_BIND_ERROR.Apply(e)
	}
	c.ListenAddr = a
	return nil
}

// d5p
type D5Params struct {
	d5sAddrStr string
	d5sAddr    *net.TCPAddr
	provider   string
	sPub       *rsa.PublicKey
	cipher     string
	user       string
	pass       string
}

func (d *D5Params) RemoteName() string {
	if d.provider != NULL {
		return d.provider + "~" + d.d5sAddrStr
	} else {
		return d.d5sAddrStr
	}
}

// without sPub field
func NewD5Params(uri string) (*D5Params, error) {
	re := regexp.MustCompile("d5://(\\w+):(\\w+)@([.:a-zA-Z0-9-]+)#(\\w+)")
	ma := re.FindStringSubmatch(uri)
	if len(ma) != 5 {
		return nil, INVALID_D5PARAMS
	}
	_, y := availableCiphers[ma[4]]
	if !y {
		return nil, UNSUPPORTED_CIPHER.Apply(ma[4])
	}
	d5sAddr, e := net.ResolveTCPAddr("tcp", ma[3])
	if e != nil {
		return nil, D5SER_UNREACHABLE.Apply(e)
	}
	return &D5Params{
		d5sAddrStr: ma[3],
		d5sAddr:    d5sAddr,
		cipher:     ma[4],
		user:       ma[1],
		pass:       ma[2],
	}, nil
}

func IsValidHost(hostport string) (ok bool, err error) {
	var h, p string
	h, p, err = net.SplitHostPort(hostport)
	if h != NULL && p != NULL && err == nil {
		ok = true
	} else if err == nil {
		err = errors.New("Invalid host address " + hostport)
	}
	return
}

// Server
type D5ServConf struct {
	Listen     string `importable:":9008"`
	Auth       string `importable:"file://_USER_PASS_FILE_PATH_"`
	Cipher     string `importable:"AES128CFB"`
	ServerName string `importable:"SERVER_NAME"`
	Verbose    int    `importable:"1"`
	DenyDest   string `importable:"OFF"`
	AuthSys    auth.AuthSys
	RSAKeys    *RSAKeyPair
	ListenAddr *net.TCPAddr
}

func (d *D5ServConf) validate() error {
	if len(d.Listen) < 1 {
		return CONF_MISS.Apply("Listen")
	}
	a, e := net.ResolveTCPAddr("tcp", d.Listen)
	if e != nil {
		return LOCAL_BIND_ERROR.Apply(e)
	}
	d.ListenAddr = a
	if len(d.Auth) < 1 {
		return CONF_MISS.Apply("Auth")
	}
	d.AuthSys, e = auth.GetAuthSysImpl(d.Auth)
	ThrowErr(e)
	if len(d.Cipher) < 1 {
		return CONF_MISS.Apply("Cipher")
	}
	_, y := availableCiphers[d.Cipher]
	if !y {
		return UNSUPPORTED_CIPHER.Apply(d.Cipher)
	}
	if d.ServerName == NULL {
		return CONF_ERROR.Apply("ServerName")
	}
	if d.RSAKeys == nil {
		return CONF_MISS.Apply("ServerPrivateKey")
	}
	if len(d.DenyDest) > 0 {
		if d.DenyDest == "OFF" || d.DenyDest == "off" {
			d.DenyDest = NULL
		} else if !regexp.MustCompile("[A-Za-z]{2}").MatchString(d.DenyDest) {
			return CONF_ERROR.Apply("DenyDest must be ISO3166-1 2-letter Country Code")
		}
	}
	return nil
}

// PEMed text
func (d *D5ServConf) Export_d5p(user *auth.User) string {
	keyBytes, e := x509.MarshalPKIXPublicKey(d.RSAKeys.pub)
	ThrowErr(e)
	header := map[string]string{
		WORD_provider: d.ServerName,
		WORD_d5p:      fmt.Sprintf("d5://%s:%s@%s#%s", user.Name, user.Pass, d.Listen, d.Cipher),
	}
	keyByte := pem.EncodeToMemory(&pem.Block{
		Type:    USER_CREDENTIAL_TYPE,
		Headers: header,
		Bytes:   keyBytes,
	})
	return string(keyByte)
}

func Generate_d5sFile(file string, rsaParam string) (e error) {
	var f *os.File
	if file == NULL {
		f = os.Stdout
	} else {
		f, e = os.OpenFile(file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		ThrowErr(e)
		e = f.Truncate(0)
		ThrowErr(e)
		defer func() {
			f.Sync()
			f.Close()
		}()
	}
	var rsaKeyBits int
	switch rsaParam {
	case "1024":
		rsaKeyBits = 1024
	default:
		rsaKeyBits = 2048
	}
	d5sConf := new(D5ServConf)
	d5sConf.RSAKeys = GenerateRSAKeyPair(rsaKeyBits)

	desc := getImportableDesc(d5sConf)
	f.WriteString("#\n# deblocus server configuration\n#\n\n")
	sk := make([]string, 0, len(desc))
	for k := range desc {
		sk = append(sk, k)
	}
	sort.Strings(sk)
	for _, k := range sk {
		defaultVal := desc[k].sType.Tag.Get("importable")
		f.WriteString(fmt.Sprintf("%-16s   %s\n", k, defaultVal))
	}
	f.WriteString("\n### Please take good care of this secret file during the server life cycle.\n")
	f.WriteString("### DON'T modify the following lines, unless you known what happens.\n\n")
	k := d5sConf.RSAKeys
	keyBytes := x509.MarshalPKCS1PrivateKey(k.priv)
	keyText := pem.EncodeToMemory(&pem.Block{
		Type:  SER_KEY_TYPE,
		Bytes: keyBytes,
	})
	f.Write(keyText)
	return
}

// public for external
func CreateClientCredential(file string, d5s *D5ServConf, user string) (e error) {
	var f *os.File
	if file == NULL {
		f = os.Stdout
	} else {
		f, e = os.OpenFile(file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		ThrowErr(e)
		e = f.Truncate(0)
		ThrowErr(e)
		defer func() {
			f.Sync()
			f.Close()
		}()
	}
	u, e := d5s.AuthSys.UserInfo(user)
	if e != nil {
		ThrowErr(e)
	}
	f.WriteString(d5s.Export_d5p(u))
	return
}

// d5p-PEM-encoding
func parse_d5pFragment(fc []byte) *D5Params {
	block, _ := pem.Decode(fc)
	// not PEM-encoded or unknown header
	ThrowIf(block == nil || block.Headers == nil || block.Headers[WORD_d5p] == "", INVALID_D5P_FRAGMENT)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	// bad public key
	ThrowIf(err != nil, INVALID_D5P_FRAGMENT)
	d5p, err := NewD5Params(block.Headers[WORD_d5p])
	ThrowErr(err)
	d5p.sPub = pub.(*rsa.PublicKey)
	if provider, y := block.Headers[WORD_provider]; y {
		d5p.provider = provider
	}
	return d5p
}

// public for external
func Parse_d5cFile(path string) *D5ClientConf {
	var d5c = new(D5ClientConf)
	var kParse = func(buf []byte) {
		key := parse_d5pFragment(buf)
		d5c.D5PList = append(d5c.D5PList, key)
	}
	desc := getImportableDesc(d5c)
	parseD5ConfFile(path, desc, kParse)
	ThrowErr(d5c.validate())
	return d5c
}

// PrivateKey for server
func parse_d5sPrivateKey(pemData []byte) *RSAKeyPair {
	block, _ := pem.Decode(pemData)
	// not PEM-encoded
	ThrowIf(block == nil, INVALID_D5S_FILE)
	if got, want := block.Type, SER_KEY_TYPE; got != want {
		ThrowErr(INVALID_D5S_FILE.Apply("unknown key type " + got))
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// bad private key
	ThrowIf(err != nil, INVALID_D5S_FILE.Apply(err))
	return &RSAKeyPair{
		priv: priv,
		pub:  &priv.PublicKey,
	}
}

// public for external
func Parse_d5sFile(path string) *D5ServConf {
	var d5s = new(D5ServConf)
	var kParse = func(buf []byte) {
		key := parse_d5sPrivateKey(buf)
		d5s.RSAKeys = key
	}
	desc := getImportableDesc(d5s)
	parseD5ConfFile(path, desc, kParse)
	ThrowErr(d5s.validate())
	return d5s
}

type keyParser func([]byte)

type FieldDescriptor struct {
	sType  *reflect.StructField
	fValue *reflect.Value
}

type ImportableFieldDesc map[string]*FieldDescriptor

// extract importable-field descriptor into map from a struct instance
// the actual parameter must be a pointer
func getImportableDesc(instance interface{}) ImportableFieldDesc {
	var desc = make(ImportableFieldDesc)
	sv := reflect.ValueOf(instance).Elem()
	st := sv.Type()
	for i := 0; i < sv.NumField(); i++ {
		v, t := sv.Field(i), st.Field(i)
		if v.CanSet() && strings.HasPrefix(string(t.Tag), "importable") {
			desc[t.Name] = &FieldDescriptor{
				sType:  &t,
				fValue: &v,
			}
		}
	}
	return desc
}

// interrupt if throw exception
func parseD5ConfFile(path string, desc ImportableFieldDesc, kParse keyParser) {
	file, e := os.Open(path)
	ThrowErr(e)
	defer file.Close()
	var (
		buf           = new(bytes.Buffer)
		r             = bufio.NewReader(file)
		kB, kE        bool
		commentRegexp = regexp.MustCompile("\\s+#")
	)
	for {
		l, _, e := r.ReadLine()
		if e != nil {
			if e == io.EOF {
				break
			}
			ThrowErr(e)
		}
		bd := len(l) > 0 && l[0] == '-'
		if bd {
			if kB {
				kE = true
			} else {
				kB = true
			}
		}
		if kB {
			buf.Write(l)
			buf.WriteByte('\n')
			if kE {
				kParse(buf.Bytes())
				kB, kE = false, false
				buf.Reset()
			}
			continue
		}
		text := strings.TrimSpace(string(l))
		if len(text) < 1 || text[0] == '#' {
			continue
		}
		if pos := commentRegexp.FindStringIndex(text); pos != nil {
			text = text[:pos[0]]
		}
		words := strings.Fields(text)
		if len(words) < 2 {
			panic(UNRECOGNIZED_SYMBOLS.Apply(words))
		}
		k, v := words[0], strings.Join(words[1:], " ")
		if d, y := desc[k]; y {
			f := d.fValue
			switch f.Kind() {
			case reflect.Bool:
				vv, e := strconv.ParseBool(v)
				ThrowErr(e)
				f.SetBool(vv)
			case reflect.Int:
				vv, e := strconv.ParseInt(v, 10, 0)
				ThrowErr(e)
				f.SetInt(vv)
			case reflect.Float32:
				vv, e := strconv.ParseFloat(v, 32)
				ThrowErr(e)
				f.SetFloat(vv)
			default:
				f.SetString(v)
			}
		} else {
			panic(UNRECOGNIZED_DIRECTIVES.Apply("at line: " + text))
		}
	}
}

func DetectRunAsServ() bool {
	p, e := osext.Executable()
	ThrowErr(e)
	p = filepath.Base(p)
	return p[0] == 0x44
}

func DetectFile(isServ bool) (string, bool) {
	p, e := osext.ExecutableFolder()
	u, e := user.Current()
	var homeDir string
	if e == nil {
		homeDir = u.HomeDir
	} else {
		homeDir = os.Getenv("HOME")
	}
	var name string
	if isServ {
		name = "deblocus.d5s"
	} else {
		name = "deblocus.d5c"
	}
	for _, f := range []string{name, // cwd
		filepath.Join(p, name),                 // bin
		filepath.Join(homeDir, name),           // home
		filepath.Join("/etc/deblocus", name)} { // /etc/deblocus
		if !IsNotExist(f) {
			return f, true
		}
	}
	return filepath.Join(p, name), false
}
