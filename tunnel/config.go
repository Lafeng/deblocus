package tunnel

import (
	"bytes"
	stdcrypto "crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/Lafeng/deblocus/auth"
	"github.com/Lafeng/deblocus/crypto"
	"github.com/Lafeng/deblocus/exception"
	"github.com/go-ini/ini"
	"github.com/kardianos/osext"
)

const (
	CF_CLIENT     = "deblocus.Client"
	CF_SERVER     = "deblocus.Server"
	CF_URL        = "URL"
	CF_KEY        = "Key"
	CF_TRANSPORT  = "Transport"
	CF_CRYPTO     = "Crypto"
	CF_PRIVKEY    = "PrivateKey"
	CF_CREDENTIAL = "Credential"
	CF_PAC        = "PAC.Server"
	CF_FILE       = "File"

	CONFIG_NAME = "deblocus.ini"
	SIZE_UNIT   = "BKMG"
)

var (
	UNRECOGNIZED_SYMBOLS = exception.New("Unrecognized symbols")
	LOCAL_BIND_ERROR     = exception.New("Local bind error")
	CONF_MISS            = exception.New("Missed field in config:")
	CONF_ERROR           = exception.New("Error field in config:")
)

type ServiceRole uint32

const (
	SR_AUTO   ServiceRole = ^ServiceRole(0)
	SR_CLIENT ServiceRole = 0x0f
	SR_SERVER ServiceRole = 0xf0
)

type ConfigContext struct {
	filepath    string
	iniInstance *ini.File
	server      *serverConf
	client      *clientConf
}

func NewConfigContextFromFile(specifiedFile string) (*ConfigContext, error) {
	var paths []string
	if specifiedFile == NULL {
		paths = []string{CONFIG_NAME} // cwd
		var ef, home string
		var err error
		// same path with exe
		ef, err = osext.ExecutableFolder()
		if err == nil {
			paths = append(paths, filepath.Join(ef, CONFIG_NAME))
		}
		// home
		if u, err := user.Current(); err == nil {
			home = u.HomeDir
		} else {
			home = os.Getenv("HOME")
		}
		if home != NULL {
			paths = append(paths, filepath.Join(home, CONFIG_NAME))
		}
		// etc
		if runtime.GOOS != "windows" {
			paths = append(paths, "/etc/deblocus/"+CONFIG_NAME)
		}
	} else {
		paths = []string{specifiedFile}
	}

	var file *string
	for _, f := range paths {
		if f != NULL && !IsNotExist(f) {
			file = &f
			break
		}
	}
	if file == nil {
		msg := fmt.Sprintf("Not found `%s` in [ %s ]\n", CONFIG_NAME, strings.Join(paths, "; "))
		msg += "Create config in typical path or specify it with option `--config/-c`."
		return nil, errors.New(msg)
	}

	iniInstance, err := ini.ShadowLoad(*file)
	return &ConfigContext{
		filepath:    *file,
		iniInstance: iniInstance,
	}, err
}

func (cc *ConfigContext) Initialize(expectedRole ServiceRole) (role ServiceRole, err error) {
	if _, err = cc.iniInstance.GetSection(CF_CLIENT); err == nil {
		role = SR_CLIENT
		cc.client, err = cc.parseClient()
	} else if _, err = cc.iniInstance.GetSection(CF_SERVER); err == nil {
		role = SR_SERVER
		cc.server, err = cc.parseServer()
	}

	if role == 0 {
		err = errors.New("No service role defined in config file")
	}
	if expectedRole != SR_AUTO && role != expectedRole {
		err = errors.New("Unexpected config file for current operation")
	}
	cc.iniInstance = nil
	return
}

func (cc *ConfigContext) LogV(expectedRole ServiceRole) int {
	if expectedRole&SR_CLIENT != 0 {
		return cc.client.Verbose
	}
	if expectedRole&SR_SERVER != 0 {
		return cc.server.Verbose
	}
	return -1
}

func (cc *ConfigContext) ClientConf() *clientConf {
	return cc.client
}

// export client ini
func (cc *ConfigContext) KeyInfo(expectedRole ServiceRole) string {
	var buf = new(bytes.Buffer)
	if expectedRole == SR_CLIENT {
		key := cc.client.transport.pubKey
		fmt.Fprintln(buf, "Credential Key in", cc.filepath)
		fmt.Fprintln(buf, "         type:", NameOfKey(key))
		fmt.Fprintln(buf, "  fingerprint:", FingerprintOfKey(key))
	} else if expectedRole == SR_SERVER {
		key := cc.server.publicKey
		fmt.Fprintln(buf, "Server Key in", cc.filepath)
		fmt.Fprintln(buf, "         type:", NameOfKey(key))
		fmt.Fprintln(buf, "  fingerprint:", FingerprintOfKey(key))
	}
	return buf.String()
}

// public for external handler
func (cc *ConfigContext) CreateClientConfig(file string, user string, addonAddr string) (err error) {
	var f *os.File
	if file == NULL {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
	}
	defer f.Sync()

	var conf = new(clientConf)
	var newIni = ini.Empty(ini.LoadOptions{AllowShadows: true})
	setFieldsDefaultValue(conf)
	// client section
	dc, _ := newIni.NewSection(CF_CLIENT)
	dc.Comment = strings.TrimSpace(_CLT_CONF_HEADER)
	dc.ReflectFrom(conf)

	// prepare server addr
	var sAddr = addonAddr
	if sAddr == NULL {
		if sAddr = findFirstUnicastAddress(); sAddr == NULL {
			sAddr = "localhost"
		}
	} else if err = IsValidHost(sAddr); err != nil {
		return
	}

	err = cc.server.generateTransportOfUser(newIni, sAddr, user)
	if err == nil {
		_, err = newIni.WriteTo(f)
		// print notice to attention on server addr
		if !isGlobalAddr(sAddr) {
			var notice = strings.Replace(_NOTICE_MOD_ADDR, "ADDR", sAddr, -1)
			fmt.Fprint(f, notice)
		}
	}
	return
}

func (cc *ConfigContext) parseClient() (cli *clientConf, err error) {
	var iniInst = cc.iniInstance
	// check client
	secDc, err := iniInst.GetSection(CF_CLIENT)
	if err != nil {
		return
	}

	cli = new(clientConf)
	err = secDc.MapTo(cli)
	if err != nil {
		return
	}

	// credential
	credSec, err := iniInst.GetSection(CF_CREDENTIAL)
	if err != nil {
		return
	}
	url, err := credSec.GetKey(CF_URL)
	if err != nil {
		return
	}

	// parse protocol URL
	transport, err := newTransport(url.String())
	if err != nil {
		return
	}

	// pubKey
	pubkeyObj, err := credSec.GetKey(CF_KEY)
	if err != nil {
		return
	}

	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkeyObj.String())
	if err != nil {
		return
	}

	pubkey, err := UnmarshalPublicKey(pubkeyBytes)
	if err != nil {
		return
	}

	// check PAC
	secPac, _ := iniInst.GetSection(CF_PAC)
	if secPac != nil && secPac.Haskey(CF_FILE) {
		cli.pacFile = secPac.Key(CF_FILE).String()
	}
	transport.pubKey = pubkey
	cli.transport = transport

	// parse transport URL
	if transportKey, err := credSec.GetKey(CF_TRANSPORT); err == nil {
		err = transport.parseTransport(transportKey.String())
		if err != nil {
			return cli, err
		}
	}

	err = cli.validate()
	return
}

func (cc *ConfigContext) parseServer() (serv *serverConf, err error) {
	ii := cc.iniInstance
	// check server
	sec, err := ii.GetSection(CF_SERVER)
	if err != nil {
		return
	}
	serv = new(serverConf)
	if err = sec.MapTo(serv); err != nil {
		return
	}

	// pub & priv key
	kSec, err := ii.GetSection(CF_PRIVKEY)
	if err != nil {
		return
	}
	key, err := kSec.GetKey(CF_KEY)
	if err != nil {
		return
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key.String())
	if err != nil {
		return
	}
	priv, err := UnmarshalPrivateKey(keyBytes)
	if err != nil {
		return
	}
	serv.privateKey = priv
	serv.publicKey = priv.(stdcrypto.Signer).Public()

	// parse transport URL
	if sec.HasKey(CF_TRANSPORT) {
		transportValues := sec.Key(CF_TRANSPORT).ValueWithShadows()
		for _, transportURL := range transportValues {
			var transport = &Transport{asServer: true}
			serv.transports = append(serv.transports, transport)
			err = transport.parseTransport(transportURL)
			if err != nil {
				return nil, err
			}
		}
	}

	err = serv.validate()
	return
}

// client config definitions
type clientConf struct {
	Listen     string `importable:":9009"`
	Verbose    int    `importable:"1"`
	pacFile    string
	ListenAddr *net.TCPAddr `ini:"-"`
	transport  *Transport
}

func (c *clientConf) validate() error {
	if c.transport == nil {
		return CONF_MISS.Apply("Not found Transport")
	}
	if c.Listen == NULL {
		return CONF_MISS.Apply("Listen")
	}
	addr, e := net.ResolveTCPAddr("tcp", c.Listen)
	if e != nil {
		return LOCAL_BIND_ERROR.Apply(e)
	}
	pkType := NameOfKey(c.transport.pubKey)
	if pkType != c.transport.pubKeyType {
		return CONF_ERROR.Apply(pkType)
	}
	if c.pacFile != NULL && IsNotExist(c.pacFile) {
		return CONF_ERROR.Apply("File Not Found " + c.pacFile)
	}
	c.ListenAddr = addr
	return nil
}

// Server config definitions
type serverConf struct {
	Auth          string       `importable:"file://_PATH_TO_USER_PASS_FILE_"`
	Cipher        string       `importable:"AES128CTR"`
	ServerName    string       `importable:"_MY_SERVER"`
	Parallels     int          `importable:"2"`
	Verbose       int          `importable:"1"`
	DenyDest      string       `importable:"OFF"`
	ErrorFeedback string       `importable:"true"` // todo: deprecated
	AuthSys       auth.AuthSys `ini:"-"`
	transports    []*Transport
	errFeedback   bool
	privateKey    stdcrypto.PrivateKey
	publicKey     stdcrypto.PublicKey
}

func (d *serverConf) validate() (e error) {
	if len(d.Auth) < 1 {
		return CONF_MISS.Apply("Auth")
	}
	d.AuthSys, e = auth.GetAuthSysImpl(d.Auth)
	if e != nil {
		return e
	}
	if len(d.Cipher) < 1 {
		return CONF_MISS.Apply("Cipher")
	}
	_, e = GetAvailableCipher(d.Cipher)
	if e != nil {
		return e
	}
	if d.ServerName == NULL {
		return CONF_MISS.Apply("ServerName")
	}
	if d.Parallels < 2 || d.Parallels > 16 {
		return CONF_ERROR.Apply("Parallels")
	}
	if d.privateKey == nil {
		return CONF_MISS.Apply("PrivateKey")
	}
	if len(d.DenyDest) > 0 {
		if d.DenyDest == "OFF" || d.DenyDest == "off" {
			d.DenyDest = NULL
		} else if !regexp.MustCompile("[A-Za-z]{2}").MatchString(d.DenyDest) {
			return CONF_ERROR.Apply("DenyDest must be ISO3166-1 2-letter Country Code")
		}
	}
	if len(d.ErrorFeedback) > 0 {
		d.errFeedback, e = strconv.ParseBool(d.ErrorFeedback)
		if e != nil {
			return CONF_ERROR.Apply("ErrorFeedback")
		}
	}
	return nil
}

// public for external handler
func CreateServerConfigTemplate(file string, keyOpt string) (err error) {
	var f *os.File
	if file == NULL {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
		defer f.Close()
	}
	defer f.Sync()

	srvConf := new(serverConf)
	srvConf.setDefaultValue()

	// uppercase algo name
	srvConf.privateKey, err = GenerateDSAKey(strings.ToUpper(keyOpt))
	if err != nil {
		return
	}

	iniInst := ini.Empty(ini.LoadOptions{AllowShadows: true})
	sSrv, _ := iniInst.NewSection(CF_SERVER)
	sSrv.Comment = strings.TrimSpace(_SER_CONF_HEADER)

	kTrans := sSrv.Key(CF_TRANSPORT)
	kTrans.Comment = "Allow this port(s) in your firewall"
	kTrans.SetValue("tcp://:9008")
	kTrans.AddShadow("kcp://:9008/fast")

	err = sSrv.ReflectFrom(srvConf)
	if err != nil {
		return
	}

	sPriv, _ := iniInst.NewSection(CF_PRIVKEY)
	keyBytes := MarshalPrivateKey(srvConf.privateKey)

	sPriv.Comment = strings.TrimSpace(_SER_CONF_MIDDLE)
	sPriv.NewKey(CF_KEY, base64.StdEncoding.EncodeToString(keyBytes))
	_, err = iniInst.WriteTo(f)
	return
}

func (d *serverConf) generateTransportOfUser(iniInst *ini.File, sAddr, user string) error {
	u, err := d.AuthSys.UserInfo(user)
	if err != nil {
		return err
	}
	keyBytes, err := MarshalPublicKey(d.publicKey)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("d5://%s:%s@%s/%s/%s/%s", u.Name, u.Pass, sAddr, d.ServerName, NameOfKey(d.publicKey), d.Cipher)
	sec, _ := iniInst.NewSection(CF_CREDENTIAL)
	sec.Comment = strings.TrimSpace(_COMMENTED_PAC_SECTION)

	// create URL
	sec.NewKey(CF_URL, url)

	// create pub-key
	sec.NewKey(CF_KEY, base64.StdEncoding.EncodeToString(keyBytes))

	// create transport
	kTrans := sec.Key(CF_TRANSPORT)
	for i, trans := range d.transports {
		switch i {
		case 0:
			kTrans.SetValue(trans.toURL())
		case 1:
			kTrans.AddShadow(trans.toURL())
		}
	}

	// todo: key of transport
	return nil
}

// set default values by field comment
// set recommended values by detecting
func (d *serverConf) setDefaultValue() {
	setFieldsDefaultValue(d)
	host, err := os.Hostname()
	if err == nil {
		host = regexp.MustCompile(`\W`).ReplaceAllString(host, "")
		d.ServerName = strings.ToUpper(host)
	}
	if crypto.HasAESHardware() == 0 {
		d.Cipher = "CHACHA12"
	}
}

func setFieldsDefaultValue(str interface{}) {
	typ := reflect.TypeOf(str)
	val := reflect.ValueOf(str)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
		val = val.Elem()
	}
	for i := 0; i < typ.NumField(); i++ {
		ft := typ.Field(i)
		fv := val.Field(i)
		imp := ft.Tag.Get("importable")
		if !ft.Anonymous && imp != NULL {
			k := fv.Kind()
			switch k {
			case reflect.String:
				fv.SetString(imp)
			case reflect.Int:
				intVal, err := strconv.ParseInt(imp, 10, 0)
				if err == nil {
					fv.SetInt(intVal)
				}
			default:
				panic(fmt.Errorf("unsupported %v", k))
			}
		}
	}
}

const _SER_CONF_HEADER = `
# -------------------------------------------------
#   deblocus server configuration
#   wiki: https://github.com/Lafeng/deblocus/wiki
# -------------------------------------------------
`

const _SER_CONF_MIDDLE = `
# Please take good care of this secret file during the server life cycle.
# DO NOT modify the following lines, unless you known what will happen.
`

const _CLT_CONF_HEADER = `
# -------------------------------------------------
#   deblocus client configuration
#   wiki: https://github.com/Lafeng/deblocus/wiki
# -------------------------------------------------
`

const _COMMENTED_PAC_SECTION = `# Optional
# [PAC.Server]
# File = mypac.js
;
;
;
# Keep Secret !!!
`

const _NOTICE_MOD_ADDR = `
# +-----------------------------------------------------------------+
#   Perhaps modify the "ADDR" to your actual public address.
# +-----------------------------------------------------------------+
`
