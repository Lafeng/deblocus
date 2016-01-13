package exception

import (
	"fmt"
	"runtime"

	log "github.com/Lafeng/deblocus/glog"
)

// injectable
var DEBUG bool

type Exception struct {
	Origin *Exception
	msg    string
}

func (e *Exception) Error() string {
	if e.Origin != nil {
		return fmt.Sprintf("%s %s", e.Origin, e.msg)
	} else {
		return e.msg
	}
}

func (e *Exception) Apply(extra interface{}) *Exception {
	return &Exception{
		Origin: e,
		msg:    fmt.Sprint(extra),
	}
}

func New(msg string) *Exception {
	return &Exception{msg: msg}
}

func Detail(err error) string {
	if err != nil && (log.V(log.LV_ERR_DETAIL) == true || DEBUG) {
		var ori = err
		if ex, y := err.(*Exception); y && ex.Origin != nil {
			ori = ex.Origin
		}
		return fmt.Sprintf("(Error:%T::%s)", ori, err)
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
		if DEBUG || bool(log.V(log.LV_ERR_STACK)) {
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
	if log.V(log.LV_ERR_DETAIL) {
		e.msg += " " + err.Error()
	}
	*ePtr = &e
	return &e
}
