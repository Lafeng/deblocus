package tunnel

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/kardianos/osext"
	"github.com/spance/deblocus/auth"
	"github.com/spance/deblocus/exception"
	log "github.com/spance/deblocus/golang/glog"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	Bye                  = syscall.Signal(0xfffb8e)
	SER_KEY_TYPE         = "deblocus/SERVER-PRIVATEKEY"
	USER_CREDENTIAL_TYPE = "deblocus/CLIENT-CREDENTIAL"
	WORD_d5p             = "D5P"
	WORD_provider        = "Provider"
	SIZE_UNIT            = "BKMG"
)

var (
	ZERO_TIME               = time.Time{}
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

func IsNotExist(file string) bool {
	_, err := os.Stat(file)
	return os.IsNotExist(err)
}

func i64HumanSize(size int64) string {
	var i = 0
	for ; i < 4; i++ {
		if size < 1024 {
			break
		}
		size = size >> 10
	}
	return strconv.FormatInt(size, 10) + string(SIZE_UNIT[i])
}

func dumpHex(title string, byteArray []byte) {
	fmt.Println("---DUMP-BEGIN-->", title)
	fmt.Print(hex.Dump(byteArray))
	fmt.Println("---DUMP-END-->", title)
}

func ipAddr(addr net.Addr) string {
	if t, y := addr.(*net.TCPAddr); y {
		return t.IP.String()
	}
	return addr.String()
}

// client
type D5ClientConf struct {
	Listen     string `importable:":9009"`
	Verbose    int    `importable:"2"`
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
	algoId     int
	user       string
	pass       string
}

func (d *D5Params) RemoteIdFull() string {
	if d.provider != NULL {
		return fmt.Sprintf("%s(d5://%s)", d.provider, d.d5sAddrStr)
	} else {
		return d.d5sAddrStr
	}
}

func (d *D5Params) RemoteId() string {
	if d.provider != NULL {
		return d.provider
	} else {
		return d.d5sAddrStr
	}
}

// without sPub field
func NewD5Params(uri string) (*D5Params, error) {
	re := regexp.MustCompile("d5://(\\w+):(\\w+)@([.:\\w]+)#(\\w+)")
	ma := re.FindStringSubmatch(uri)
	if len(ma) != 5 {
		return nil, INVALID_D5PARAMS
	}
	algoId, y := cipherLiteral[ma[4]]
	if !y {
		return nil, UNSUPPORTED_CIPHER.Apply(ma[4])
	}
	d5sAddr, e := net.ResolveTCPAddr("tcp", ma[3])
	if e != nil {
		return nil, D5SER_UNREACHABLE.Apply(e)
	}
	if log.V(2) {
		log.Infof("D5Params: %q\n", ma[1:])
	}
	return &D5Params{
		d5sAddrStr: ma[3],
		d5sAddr:    d5sAddr,
		algoId:     algoId,
		user:       ma[1],
		pass:       ma[2],
	}, nil
}

// Server
type D5ServConf struct {
	Listen     string `importable:":9008"`
	AuthTable  string `importable:"file:///PATH/YOUR_AUTH_FILE_PATH"`
	Algo       string `importable:"AES128CFB"`
	ServerName string `importable:"SERVER_INDENTIFIER"`
	Verbose    int    `importable:"2"`
	AlgoId     int
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
	if len(d.AuthTable) < 1 {
		return CONF_MISS.Apply("AuthTable")
	}
	d.AuthSys, e = auth.GetAuthSysImpl(d.AuthTable)
	ThrowErr(e)
	if len(d.Algo) < 1 {
		return CONF_MISS.Apply("Algo")
	}
	algoId, y := cipherLiteral[d.Algo]
	if !y {
		return UNSUPPORTED_CIPHER.Apply(d.Algo)
	}
	d.AlgoId = algoId
	if d.ServerName == NULL {
		return CONF_ERROR.Apply("ServerName")
	}
	if d.RSAKeys == nil {
		return CONF_MISS.Apply("ServerPrivateKey")
	}
	return nil
}

// PEMed text
func (d *D5ServConf) Export_d5p(user *auth.User) string {
	keyBytes, e := x509.MarshalPKIXPublicKey(d.RSAKeys.pub)
	ThrowErr(e)
	header := map[string]string{
		WORD_provider: d.ServerName,
		WORD_d5p:      fmt.Sprintf("d5://%s:%s@%s#%s", user.Name, user.Pass, d.Listen, d.Algo),
	}
	keyByte := pem.EncodeToMemory(&pem.Block{
		Type:    USER_CREDENTIAL_TYPE,
		Headers: header,
		Bytes:   keyBytes,
	})
	if strings.HasPrefix(d.Listen, ":") {
		keyByte = append(keyByte, "\n# !!! Warning: You may need to complete server address manually.\n"...)
	}
	return string(keyByte)
}

func Generate_d5sFile(file string, d5sConf *D5ServConf) (*RSAKeyPair, error) {
	var f *os.File
	if IsNotExist(file) {
		f = os.Stdout
	} else {
		f, e := os.Create(file)
		ThrowErr(e)
		defer f.Close()
	}
	if d5sConf == nil {
		d5sConf = new(D5ServConf)
		d5sConf.RSAKeys = GenerateRSAKeyPair()
	}
	desc := getImportableDesc(d5sConf)
	f.WriteString("#\n# deblocus server configuration\n#\n")
	for k, d := range desc {
		defaultVal := d.sType.Tag.Get("importable")
		f.WriteString(fmt.Sprintf("%-16s   %s\n", k, defaultVal))
	}
	f.WriteString("#\n# Please take good care of this secret file during the server life cycle.\n")
	f.WriteString("# DON'T modify the following lines, unless you known what happens.\n#\n")
	k := d5sConf.RSAKeys
	keyBytes := x509.MarshalPKCS1PrivateKey(k.priv)
	keyText := pem.EncodeToMemory(&pem.Block{
		Type:  SER_KEY_TYPE,
		Bytes: keyBytes,
	})
	f.Write(keyText)
	return k, nil
}

// public for external
func CreateClientCredential(d5s *D5ServConf, user string) {
	u, e := d5s.AuthSys.UserInfo(user)
	if e != nil {
		ThrowErr(e)
	}
	fmt.Println(d5s.Export_d5p(u))
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
	parent *FieldDescriptor
}

type ImportableFieldDesc map[string]*FieldDescriptor

// extract importabe-field descriptor into map from a struct instance
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
		buf    = new(bytes.Buffer)
		r      = bufio.NewReader(file)
		kB, kE bool
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
	return p[0] < 97
}

func DetectFile(isServ bool) (string, bool) {
	p, e := osext.ExecutableFolder()
	u, e := user.Current()
	ThrowErr(e)
	var name string
	if isServ {
		name = "deblocus.d5s"
	} else {
		name = "deblocus.d5c"
	}
	for _, f := range []string{filepath.Join(p, name), filepath.Join(u.HomeDir, name), filepath.Join("/etc/deblocus", name)} {
		if !IsNotExist(f) {
			return f, true
		}
	}
	return filepath.Join(p, name), false
}
