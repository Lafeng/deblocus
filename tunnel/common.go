package tunnel

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"reflect"
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
	SIZEOF_INT int
)

func init() {
	rand.Seed(time.Now().UnixNano())
	var aint int
	SIZEOF_INT = int(unsafe.Sizeof(aint))
}

func nvl(v interface{}, def interface{}) interface{} {
	if v == nil {
		return def
	}
	return v
}

func SubstringBefore(str, sep string) string {
	if p := strings.Index(str, sep); p > 0 {
		return str[:p]
	} else {
		return str
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
		n = rand.Int63n(max)
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

func randArray3(arrayLen int) []byte {
	array := make([]byte, arrayLen+7)
	loop := len(array) >> 3
	var n int64
	for i := 0; i < loop; i++ {
		n = rand.Int63()
		binary.LittleEndian.PutUint64(array[i<<3:], uint64(n))
	}
	return array[:arrayLen]
}

var myRand = &lockedSource{
	rand.NewSource(time.Now().UnixNano()),
	new(sync.Mutex),
}

type lockedSource struct {
	rand.Source
	*sync.Mutex
}

func (r *lockedSource) setSeed() {
	r.Lock()
	r.Seed(time.Now().UnixNano())
	r.Unlock()
}

// make len=arrayLen array, and filled with len=randLen pseudorandom
func randArray(arrayLen int) []byte {
	newLen := (arrayLen + 7) >> 3 << 3
	array := make([]byte, newLen)

	myRand.Lock()
	for i := 0; i < newLen; i += 8 {
		binary.LittleEndian.PutUint64(array[i:i+8], uint64(myRand.Int63()))
	}
	myRand.Unlock()

	return array[:arrayLen]
}

func convert(raw []int) []byte {
	// Get the slice header
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&raw))

	// The length and capacity of the slice are different.
	header.Len *= SIZEOF_INT
	header.Cap *= SIZEOF_INT

	// Convert slice header to an []int32
	return *(*[]byte)(unsafe.Pointer(&header))
}

func hash20(byteArray []byte) []byte {
	sha := sha1.New()
	sha.Write(byteArray)
	return sha.Sum(nil)
}

func ito4b(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}
