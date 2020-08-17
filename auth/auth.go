package auth

import (
	"strings"

	"github.com/Lafeng/deblocus/exception"
)

var (
	NO_SUCH_USER          = exception.New("No such user")
	AUTH_FAILED           = exception.New("Auth failed")
	UNIMPLEMENTED_AUTHSYS = exception.New("Unimplemented authsys")
	INVALID_AUTH_CONF     = exception.New("Invalid Auth config")
	INVALID_AUTH_PARAMS   = exception.New("Invalid Auth params")
)

type AuthSys interface {
	Authenticate(user, passwd string) (bool, error)
	AddUser(user *User) error
	UserInfo(user string) (*User, error)
	Stats() string
	Reload() error
}

type User struct {
	Name string
	Pass string
}

func GetAuthSysImpl(proto string) (AuthSys, error) {
	sep := strings.Index(proto, "://")
	if sep > 0 {
		switch proto[:sep] {
		case "file":
			return NewFileAuthSys(proto[sep+3:])
		}
	}
	return nil, UNIMPLEMENTED_AUTHSYS.Apply("for " + proto)
}
