package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type FileAuthSys struct {
	path string
	lock *sync.RWMutex
	db   map[string]*User
}

func NewFileAuthSys(path string) (AuthSys, error) {
	fa := &FileAuthSys{
		path: path,
		lock: &sync.RWMutex{},
		db:   make(map[string]*User),
	}
	fa.lock.Lock()
	defer fa.lock.Unlock()
	return fa, fa.load()
}

func (fa *FileAuthSys) load() error {
	f, e := os.Open(fa.path)
	if os.IsNotExist(e) {
		return INVALID_AUTH_CONF.Apply("NotFound: " + fa.path)
	}
	defer f.Close()

	r := bufio.NewScanner(f)
	for r.Scan() {
		line := r.Text()
		if len(line) > 0 {
			arr := strings.SplitN(line, ":", 2)
			if len(arr) < 2 {
				return INVALID_AUTH_CONF.Apply("at line: " + line)
			}
			fa.db[arr[0]] = &User{arr[0], arr[1]}
		}
	}
	return nil
}

func (a *FileAuthSys) Authenticate(user, passwd string) (bool, error) {
	a.lock.RLock()
	defer a.lock.RUnlock()

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
	a.lock.RLock()
	defer a.lock.RUnlock()

	if u, y := a.db[user]; y {
		return u, nil
	} else {
		return nil, NO_SUCH_USER.Apply(user)
	}
}

func (a *FileAuthSys) Stats() string {
	a.lock.RLock()
	defer a.lock.RUnlock()

	return fmt.Sprintf("AuthSys=fileAuth len(user)=%d\n", len(a.db))
}

func (a *FileAuthSys) Reload() error {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.db = make(map[string]*User)
	return a.load()
}
