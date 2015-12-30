package tunnel

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	Bye = syscall.Signal(0xfffb8e)
)

var (
	ZERO_TIME  = time.Time{}
	WORD_SIZE  int
	BYTE_ORDER int // 0 is Little Endian, 1 is Big Endian
)

func init() {
	// default global rand
	rand.Seed(time.Now().UnixNano())
	var one uint32 = 1
	byte4 := (*[4]byte)(unsafe.Pointer(&one))
	BYTE_ORDER = int(byte4[3])
	WORD_SIZE = int(unsafe.Sizeof(uintptr(1)))
}

var myRand = &lockedSource{
	rand.NewSource(time.Now().UnixNano()),
	new(sync.Mutex),
}

type lockedSource struct {
	rand.Source
	*sync.Mutex
}

func (r *lockedSource) setSeed(seed int) {
	r.Lock()
	if seed > 0 {
		r.Seed(int64(seed))
	} else {
		r.Seed(int64(time.Now().Nanosecond()))
	}
	r.Unlock()
}

func (r *lockedSource) Int63n(n int64) int64 {
	r.Lock()
	defer r.Unlock()
	m := r.Int63()
	if m < n {
		return m
	}
	return m % n
}

// make len=arrayLen array, and filled with len=randLen pseudorandom
func randArray(arrayLen int) []byte {
	newLen := (arrayLen + 7) >> 3 << 3
	array := make([]byte, newLen)

	ptr := (uintptr)(unsafe.Pointer(&array[0]))
	ptrEnd := ptr + uintptr(newLen)
	myRand.Lock()
	for ; ptr < ptrEnd; ptr += 8 {
		*(*int64)(unsafe.Pointer(ptr)) = myRand.Int63()
	}
	myRand.Unlock()

	return array[:arrayLen]
}

func nvl(v interface{}, def interface{}) interface{} {
	if v == nil {
		return def
	}
	return v
}

func SubstringBefore(str, sep string) (string, string) {
	if p := strings.Index(str, sep); p > 0 {
		return str[:p], str[p:]
	} else {
		return str, NULL
	}
}

func SubstringLastBefore(str, sep string) string {
	if p := strings.LastIndex(str, sep); p > 0 {
		return str[:p]
	} else {
		return str
	}
}

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

func randomRange(min, max int64) (n int64) {
	for ; n < min; n %= max {
		n = myRand.Int63n(max)
	}
	return n
}

func randomHalving(n int64) int64 {
	var h, q = n >> 1, n >> 2
	n = randomRange(q, n)
	return h - n
}

func dumpHex(title string, byteArray []byte) {
	fmt.Println("---DUMP-BEGIN-->", title)
	fmt.Print(hex.Dump(byteArray))
	fmt.Println("---DUMP-END-->", title)
}

func ipAddr(addr net.Addr) string {
	switch addr.(type) {
	case *net.TCPAddr:
		return addr.(*net.TCPAddr).IP.String()
	case *net.UDPAddr:
		return addr.(*net.UDPAddr).IP.String()
	case *net.IPAddr:
		return addr.(*net.IPAddr).IP.String()
	}
	return addr.String()
}

func ThrowErr(e interface{}) {
	if e != nil {
		panic(e)
	}
}

func ThrowIf(condition bool, e interface{}) {
	if condition {
		panic(e)
	}
}

func SafeClose(conn net.Conn) {
	defer func() {
		_ = recover()
	}()
	if conn != nil {
		conn.Close()
	}
}

func closeR(conn net.Conn) {
	defer func() { _ = recover() }()
	if t, y := conn.(*net.TCPConn); y {
		t.CloseRead()
	} else {
		conn.Close()
	}
}

func closeW(conn net.Conn) {
	defer func() { _ = recover() }()
	if t, y := conn.(*net.TCPConn); y {
		t.CloseWrite()
	} else {
		conn.Close()
	}
}

func IsValidHost(hostport string) (ok bool, err error) {
	var h, p string
	h, p, err = net.SplitHostPort(hostport)
	if h != NULL && p != NULL && err == nil {
		ok = true
	} else if err == nil {
		err = errors.New("Invalid host address " + hostport)
	}
	return
}

func IsTimeout(e error) bool {
	if err, y := e.(net.Error); y {
		return err.Timeout()
	}
	return false
}

func setRTimeout(conn net.Conn) {
	e := conn.SetReadDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	ThrowErr(e)
}

func setWTimeout(conn net.Conn) {
	e := conn.SetWriteDeadline(time.Now().Add(GENERAL_SO_TIMEOUT))
	ThrowErr(e)
}

func hash160(byteArray []byte) []byte {
	sha := sha1.New()
	sha.Write(byteArray)
	return sha.Sum(nil)
}

func hash256(msg []byte) []byte {
	sha := sha256.New()
	sha.Write(msg)
	return sha.Sum(nil)
}

func ito4b(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}
