package exception

import (
	"fmt"
	log "github.com/Lafeng/deblocus/golang/glog"
	"runtime"
)

// injection
var DEBUG bool

type Exception struct {
	msg     string
	code    int
	warning bool
}

func (e *Exception) Error() string {
	return e.msg
}

func (e *Exception) Code() int {
	return e.code
}

func (e *Exception) Warning() bool {
	return e.warning
}

func (e *Exception) Apply(appendage interface{}) *Exception {
	newE := new(Exception)
	newE.code = e.code
	newE.msg = fmt.Sprintf("%s %v", e.msg, appendage)
	return newE
}

func NewW(msg string) *Exception {
	return &Exception{msg: msg, warning: true}
}

func New(code int, msg string) *Exception {
	return &Exception{msg: msg, code: code}
}

func CatchException(e interface{}) bool {
	if e != nil {
		if s, y := e.(string); y {
			log.Warningln(s)
		} else if ex, y := e.(*Exception); y && ex.warning {
			log.Errorln(ex.msg)
			return true
		} else {
			log.Errorln(e)
		}
		if DEBUG || bool(log.V(3)) {
			buf := make([]byte, 1600)
			runtime.Stack(buf, false)
			log.DirectPrintln(string(buf))
		}
		return true
	}
	return false
}

func ErrorOf(e interface{}) (err error, ie bool) {
	if e == nil {
		return nil, false
	} else {
		ie = true
	}
	switch e.(type) {
	case error:
		err = e.(error)
	default:
		err = &Exception{msg: fmt.Sprintf("%v", e)}
	}
	return
}
