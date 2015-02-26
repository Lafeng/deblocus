package auth

import (
	"bufio"
	"github.com/spance/deblocus/exception"
	"os"
	"strings"
)

var (
	NO_SUCH_USER          = exception.NewW("No such user")
	AUTH_FAILED           = exception.NewW("Auth failed")
	UNIMPLEMENTED_AUTHSYS = exception.NewW("Unimplemented authsys")
	INVALID_AUTH_CONF     = exception.NewW("Invalid Auth config")
	INVALID_AUTH_PARAMS   = exception.NewW("Invalid Auth params")
)

type AuthSys interface {
	Authenticate(input []byte) (bool, error)
	AddUser(user *User) error
	UserInfo(user string) (*User, error)
}

type User struct {
	Name string
	Pass string
}

func GetAuthSysImpl(proto string) (AuthSys, error) {
	if strings.HasPrefix(proto, "file://") {
		return NewFileAuthSys(proto[7:])
	}
	return nil, UNIMPLEMENTED_AUTHSYS.Apply("for " + proto)
}

type FileAuthSys struct {
	path string
	db   map[string]*User
}

func NewFileAuthSys(path string) (AuthSys, error) {
	sys := &FileAuthSys{
		path: path,
		db:   make(map[string]*User),
	}
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return nil, INVALID_AUTH_CONF.Apply("NotFound: " + path)
	}
	defer f.Close()
	r := bufio.NewScanner(f)
	for r.Scan() {
		line := r.Text()
		if len(line) > 0 {
			arr := strings.SplitN(line, ":", 2)
			if len(arr) < 2 {
				return nil, INVALID_AUTH_CONF.Apply("at line: " + line)
			}
			sys.db[arr[0]] = &User{arr[0], arr[1]}
		}
	}
	return sys, nil
}

func (a *FileAuthSys) Authenticate(input []byte) (bool, error) {
	arr := strings.SplitN(string(input), "\x00", 2)
	if len(arr) != 2 {
		return false, INVALID_AUTH_PARAMS
	}
	if _, y := a.db[arr[0]]; y {
		return y, nil
	} else {
		return false, AUTH_FAILED
	}
}
func (a *FileAuthSys) AddUser(user *User) error {
	return nil
}
func (a *FileAuthSys) UserInfo(user string) (*User, error) {
	if u, y := a.db[user]; y {
		return u, nil
	} else {
		return nil, NO_SUCH_USER.Apply(user)
	}
}
