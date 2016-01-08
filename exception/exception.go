package exception

import (
	"fmt"
	"runtime"

	log "github.com/Lafeng/deblocus/golang/glog"
)

// injectable
var DEBUG bool

type Exception struct {
	msg string
}

func (e *Exception) Error() string {
	return e.msg
}

func (e *Exception) Apply(appendage interface{}) *Exception {
	newE := new(Exception)
	newE.msg = fmt.Sprintf("%s %v", e.msg, appendage)
	return newE
}

func New(msg string) *Exception {
	return &Exception{msg: msg}
}

func Detail(err error) string {
	if err != nil && (log.V(1) == true || DEBUG) {
		return fmt.Sprintf("(Error:%T::%s)", err, err)
	}
	return ""
}

// if ( [re] != nil OR [err] !=nil ) then return true
// and set [err] to [re] if [re] != nil
func Catch(re interface{}, err *error) bool {
	var ex error
	if re != nil {
		switch rex := re.(type) {
		case error:
			ex = rex
		default:
			ex = fmt.Errorf("%v", re)
		}
		// print recovered error
		if DEBUG || bool(log.V(1)) {
			buf := make([]byte, 1600)
			n := runtime.Stack(buf, false)
			errStack := ex.Error() + "\n"
			errStack += string(buf[:n])
			log.DirectPrintln(errStack)
		}
	}
	if ex != nil {
		if err != nil {
			*err = ex
		}
		return true
	}
	return err != nil && *err != nil
}

func Spawn(ePtr *error, format string, args ...interface{}) error {
	var err error
	if err = *ePtr; err == nil {
		return nil
	}
	var e Exception
	e.msg = fmt.Sprintf(format, args...)
	if log.V(1) {
		e.msg += " " + err.Error()
	}
	*ePtr = &e
	return &e
}
