package auth

import (
	"bufio"
	"os"
	"strings"
)

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

func (a *FileAuthSys) Authenticate(user, passwd string) (bool, error) {
	if u, y := a.db[user]; y {
		if u.Pass == passwd {
			return true, nil
		} else {
			return false, AUTH_FAILED
		}
	} else {
		return false, NO_SUCH_USER.Apply(user)
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
