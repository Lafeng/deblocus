package tunnel

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/Lafeng/deblocus/auth"
	"github.com/Lafeng/deblocus/exception"
	"github.com/go-ini/ini"
	"github.com/kardianos/osext"
)

const (
	CF_CLIENT     = "deblocus.Client"
	CF_SERVER     = "deblocus.Server"
	CF_URL        = "URL"
	CF_KEY        = "Key"
	CF_CRYPTO     = "Crypto"
	CF_PRIVKEY    = "PrivateKey"
	CF_CREDENTIAL = "Credential"

	CONFIG_NAME = "deblocus.ini"
	SIZE_UNIT   = "BKMG"
)

var (
	UNRECOGNIZED_SYMBOLS = exception.New("Unrecognized symbols")
	LOCAL_BIND_ERROR     = exception.New("Local bind error")
	CONF_MISS            = exception.New("Missed field in config:")
	CONF_ERROR           = exception.New("Error field in config:")
)

type ServerRole uint32

const (
	SR_AUTO   ServerRole = ^ServerRole(0)
	SR_CLIENT ServerRole = 0x0f
	SR_SERVER ServerRole = 0xf0
)

type ConfigMan struct {
	iniInstance *ini.File
	sConf       *serverConf
	cConf       *clientConf
}

func DetectConfig(specifiedFile string) (*ConfigMan, error) {
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
		msg += "Create config in typical path or specify it with option `--config`."
		return nil, errors.New(msg)
	}

	iniInstance, err := ini.Load(*file)
	return &ConfigMan{iniInstance: iniInstance}, err
}

func (cman *ConfigMan) InitConfigByRole(expectedRole ServerRole) (r ServerRole, err error) {
	if expectedRole&SR_CLIENT != 0 {
		if _, err = cman.iniInstance.GetSection(CF_CLIENT); err == nil {
			r |= SR_CLIENT
			cman.cConf, err = cman.ParseClientConf()
		}
		if err != nil {
			goto abort
		}
	}

	if expectedRole&SR_SERVER != 0 {
		if _, err = cman.iniInstance.GetSection(CF_SERVER); err == nil {
			r |= SR_SERVER
			cman.sConf, err = cman.ParseServConf()
		}
		if err != nil {
			goto abort
		}
	}

abort:
	return r, err
}

func (cman *ConfigMan) LogV(expectedRole ServerRole) int {
	if expectedRole&SR_SERVER != 0 {
		return cman.sConf.Verbose
	}
	if expectedRole&SR_CLIENT != 0 {
		return cman.cConf.Verbose
	}
	return -1
}

func (cman *ConfigMan) ListenAddr(expectedRole ServerRole) *net.TCPAddr {
	if expectedRole&SR_SERVER != 0 {
		return cman.sConf.ListenAddr
	}
	if expectedRole&SR_CLIENT != 0 {
		return cman.cConf.ListenAddr
	}
	return nil
}

// client config definitions
type clientConf struct {
	Listen     string       `importable:":9009"`
	Verbose    int          `importable:"1"`
	ListenAddr *net.TCPAddr `ini:"-"`
	connInfo   *connectionInfo
}

func (c *clientConf) validate() error {
	if c.connInfo == nil {
		return CONF_MISS.Apply("Not found credential")
	}
	if c.Listen == NULL {
		return CONF_MISS.Apply("Listen")
	}
	a, e := net.ResolveTCPAddr("tcp", c.Listen)
	if e != nil {
		return LOCAL_BIND_ERROR.Apply(e)
	}
	pkType := NameOfKey(c.connInfo.sPubKey)
	if pkType != c.connInfo.pkType {
		return CONF_ERROR.Apply(pkType)
	}
	c.ListenAddr = a
	return nil
}

type connectionInfo struct {
	sAddr    string
	provider string
	cipher   string
	user     string
	pass     string
	pkType   string
	sPubKey  crypto.PublicKey
}

func (d *connectionInfo) RemoteName() string {
	if d.provider != NULL {
		return d.provider + "~" + d.sAddr
	} else {
		return d.sAddr
	}
}

func newConnectionInfo(uri string) (*connectionInfo, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if url.Scheme != "d5" {
		return nil, CONF_ERROR.Apply(url.Scheme)
	}

	_, err = net.ResolveTCPAddr("tcp", url.Host)
	if err != nil {
		return nil, HOST_UNREACHABLE.Apply(err)
	}
	var tmp string
	var info = connectionInfo{sAddr: url.Host}
	if len(url.Path) > 1 {
		info.provider, tmp = SubstringBefore(url.Path[1:], "=")
	}
	if info.provider == NULL {
		return nil, CONF_MISS.Apply("Provider")
	}

	info.pkType, tmp = SubstringBefore(tmp[1:], "/")
	info.cipher = tmp[1:]
	_, err = GetAvailableCipher(info.cipher)
	if err != nil {
		return nil, err
	}

	user := url.User
	if user == nil || user.Username() == NULL {
		return nil, CONF_MISS.Apply("user")
	}
	passwd, ok := user.Password()
	if !ok || passwd == NULL {
		return nil, CONF_MISS.Apply("passwd")
	}
	info.user = user.Username()
	info.pass = passwd
	return &info, nil
}

// public for external handler
func (cman *ConfigMan) CreateClientConfig(file string, user string, addonAddr string) (err error) {
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

	conf := new(clientConf)
	setFieldsDefaultValue(conf)
	ii := ini.Empty()
	// client section
	dc, _ := ii.NewSection(CF_CLIENT)
	dc.Comment = _d5c_header[1:]
	dc.ReflectFrom(conf)
	// prepare server addr
	cman.sConf.Listen = addonAddr
	err = cman.sConf.generateConnInfoOfUser(ii, user)
	if err == nil {
		_, err = ii.WriteTo(f)
	}
	return
}

// public for external
func (cman *ConfigMan) ParseClientConf() (d5c *clientConf, err error) {
	ii := cman.iniInstance
	dc, err := ii.GetSection(CF_CLIENT)
	if err != nil {
		return
	}
	d5c = new(clientConf)
	err = dc.MapTo(d5c)
	if err != nil {
		return
	}
	cr, err := ii.GetSection(CF_CREDENTIAL)
	if err != nil {
		return
	}
	url, err := cr.GetKey(CF_URL)
	if err != nil {
		return
	}
	connInfo, err := newConnectionInfo(url.String())
	if err != nil {
		return
	}
	pubkeyObj, err := cr.GetKey(CF_KEY)
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
	connInfo.sPubKey = pubkey
	d5c.connInfo = connInfo
	err = d5c.validate()
	return
}

// Server config definitions
type serverConf struct {
	Listen     string       `importable:":9008"`
	Auth       string       `importable:"file://_USER_PASS_FILE_PATH_"`
	Cipher     string       `importable:"AES128CTR"`
	ServerName string       `importable:"_MY_SERVER"`
	Verbose    int          `importable:"1"`
	DenyDest   string       `importable:"OFF"`
	AuthSys    auth.AuthSys `ini:"-"`
	ListenAddr *net.TCPAddr `ini:"-"`
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
}

func (d *serverConf) validate() error {
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
	return nil
}

// public for external handler
func (cman *ConfigMan) ParseServConf() (d5s *serverConf, err error) {
	ii := cman.iniInstance
	sec, err := ii.GetSection(CF_SERVER)
	if err != nil {
		return
	}
	d5s = new(serverConf)
	if err = sec.MapTo(d5s); err != nil {
		return
	}
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
	d5s.privateKey = priv
	d5s.publicKey = priv.(crypto.Signer).Public()
	err = d5s.validate()
	return
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

	d5sConf := new(serverConf)
	setFieldsDefaultValue(d5sConf)
	d5sConf.privateKey, err = GenerateECCKey(keyOpt)
	if err != nil {
		return
	}

	ii := ini.Empty()
	ds, _ := ii.NewSection(CF_SERVER)
	ds.Comment = _d5s_header[1:]
	err = ds.ReflectFrom(d5sConf)
	if err != nil {
		return
	}
	ks, _ := ii.NewSection(CF_PRIVKEY)
	keyBytes := MarshalPrivateKey(d5sConf.privateKey)

	ks.Comment = _d5s_middle[1:]
	ks.NewKey(CF_KEY, base64.StdEncoding.EncodeToString(keyBytes))
	_, err = ii.WriteTo(f)
	return
}

func (d *serverConf) generateConnInfoOfUser(ii *ini.File, user string) error {
	u, err := d.AuthSys.UserInfo(user)
	if err != nil {
		return err
	}
	keyBytes, err := MarshalPublicKey(d.publicKey)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("d5://%s:%s@%s/%s=%s/%s", u.Name, u.Pass, d.Listen, d.ServerName, NameOfKey(d.publicKey), d.Cipher)
	sec, _ := ii.NewSection(CF_CREDENTIAL)
	sec.NewKey(CF_URL, url)
	sec.NewKey(CF_KEY, base64.StdEncoding.EncodeToString(keyBytes))
	return nil
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

const _d5s_header = `
# ----------------------------------------
# deblocus server configuration
# wiki: https://github.com/Lafeng/deblocus/wiki
# ----------------------------------------
`

const _d5s_middle = `
### Please take good care of this secret file during the server life cycle.
### DO NOT modify the following lines, unless you known what will happen.
`

const _d5c_header = `
# ----------------------------------------
# deblocus client configuration
# wiki: https://github.com/Lafeng/deblocus/wiki
# ----------------------------------------
`
