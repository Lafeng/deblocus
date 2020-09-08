package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	log "github.com/Lafeng/deblocus/glog"
)

var (
	cltAddr = "127.0.0.1:"
	svrAddr = "127.0.0.2:"
	dstAddr = "127.0.0.3:"
	client  *multiplexer
	server  *multiplexer
)

func initAddonArgs(defVal int) int {
	var v int
	flag.IntVar(&v, "vv", defVal, "log verbose")
	flag.Parse()
	return v
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	v := initAddonArgs(0)
	log.SetLogOutput("")
	log.SetLogVerbose(v)
	cltAddr += strconv.FormatInt(randomRange(1, 1<<13)+3e4, 10)
	svrAddr += strconv.FormatInt(randomRange(1, 1<<13)+3e4, 10)
	dstAddr += strconv.FormatInt(randomRange(1, 1<<13)+3e4, 10)
	fmt.Println("=== deblocus TEST ===")
	printArgLine("logV", v)
	printArgLine("cltAddr", cltAddr)
	printArgLine("svrAddr", svrAddr)
	printArgLine("dstAddr", dstAddr)
	fmt.Println()
}

func printArgLine(name string, val interface{}) {
	fmt.Printf("%11s = %v\n", name, val)
}

func startEmulation() {
	if client != nil {
		return
	}
	client = newClientMultiplexer()
	go startDestSvr()
	go startServer()
	rest(1) // waiting for server listen
	go startClient(1)
	rest(1) // waiting for server and client
	tunSize := client.pool.Len()
	// assert tunSize==1
	if tunSize != 1 {
		panic(fmt.Sprintf("client tun size=%d", tunSize))
	}
}

func rest(scale time.Duration) {
	if scale <= 0 {
		scale = 50
	} else {
		scale *= 100
	}
	time.Sleep(scale * time.Millisecond)
}

func startDestSvr() {
	ln, e := net.Listen("tcp", dstAddr)
	ThrowErr(e)
	defer ln.Close()
	for {
		dconn, e := ln.Accept()
		ThrowErr(e)
		go func(conn net.Conn) {
			defer conn.Close()
			for {
				conn.SetReadDeadline(time.Now().Add(time.Second * 10))
				buf, e := ReadFullByLen(2, conn)
				nr := len(buf)
				if e != nil || nr == 0 || (nr == 1 && buf[0] == 0) {
					break
				} else {
					nw, e := conn.Write(buf)
					ThrowErr(e)
					ThrowIf(nw != nr, fmt.Sprintf("nr=%d nw=%d", nr, nw))
				}
			}
		}(dconn)
	}
}

func startServer() {
	ln, e := net.Listen("tcp", svrAddr)
	ThrowErr(e)
	defer ln.Close()
	server = newServerMultiplexer()
	for {
		conn, e := ln.Accept()
		ThrowErr(e)
		go server.Listen(NewConn(conn.(*net.TCPConn), nullCipherKit), nil, 0)
	}
}

func startClient(size int) {
	for i := 0; i < size; i++ {
		conn, e := net.Dial("tcp", svrAddr)
		ThrowErr(e)
		go client.Listen(NewConn(conn.(*net.TCPConn), nullCipherKit), nil, 0)
	}
	ln, e := net.Listen("tcp", cltAddr)
	ThrowErr(e)
	defer ln.Close()

	for {
		conn, e := ln.Accept()
		ThrowErr(e)
		go client.HandleRequest("T", conn, dstAddr)
	}
}

func randomBuffer(buf []byte) (n uint16) {
	step := 32
	io.ReadFull(rand.Reader, buf[:step])
	for i := step << 1; i <= len(buf); i <<= 1 {
		copy(buf[i/2:i], buf[:i/2])
	}
	for n < 8 || n > 0xfff0 {
		nb := make([]byte, 2)
		io.ReadFull(rand.Reader, nb)
		n = binary.BigEndian.Uint16(nb)
	}
	binary.BigEndian.PutUint16(buf, n-2)
	return
}

func assertLength(t *testing.T, v ...interface{}) {
	for i := 0; i < len(v); i += 3 {
		_len := reflect.ValueOf(v[i+1]).Len()
		if _len != v[i+2].(int) {
			t.Errorf("len(%s) = %d", v[i], _len)
		}
	}
}

func checkFinishedLength(t *testing.T) {
	server.router.clean()
	client.router.clean()
	// assert server.registry.len==0
	assertLength(t, "server.registry", server.router.registry, 0)
	// assert client.registry.len==0
	assertLength(t, "client.registry", client.router.registry, 0)
}

func TestSingleRequest(t *testing.T) {
	startEmulation()
	conn, e := net.Dial("tcp", cltAddr)
	ThrowErr(e)
	rest(1)
	assertLength(t, "client.registry", client.router.registry, 1)
	buf0 := make([]byte, 0xffff)
	buf1 := make([]byte, 0xffff)
	for i := 0; i < 10; i++ {
		n := randomBuffer(buf0)
		nw, e := conn.Write(buf0[:n])
		ThrowErr(e)
		nr, e := io.ReadFull(conn, buf1[:n-2])
		ThrowErr(e)
		if log.V(3) {
			fmt.Printf("\tsend=%d recv=%d\n", nw, nr)
		}
		if !bytes.Equal(buf0[2:n], buf1[:nr]) {
			t.Errorf("sent is inconsistent with recv. nw=%d nr=%d\n", nw, nr)
		}
	}
	conn.Close()
	rest(2)
	checkFinishedLength(t)
}

func TestConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			conn, e := net.Dial("tcp", cltAddr)
			ThrowErr(e)
			if log.V(2) {
				fmt.Printf("\tthread=%d/ start\n", j)
			}
			defer conn.Close()
			buf0 := make([]byte, 0xffff)
			buf1 := make([]byte, 0xffff)
			for k := 0; k < 99; k++ {
				n := randomBuffer(buf0)
				nw, e := conn.Write(buf0[:n])
				ThrowErr(e)
				ThrowIf(nw != int(n), fmt.Sprintf("nr=%d nw=%d", n, nw))
				conn.SetReadDeadline(time.Now().Add(time.Second * 4))
				nr, e := io.ReadFull(conn, buf1[:n-2])
				if e != nil {
					if ne, y := e.(net.Error); y && ne.Timeout() {
						continue
					} else {
						ThrowErr(e)
					}
				}
				if log.V(2) {
					fmt.Printf("\tthread=%d/%d send=%d recv=%d\n", j, k, nw, nr)
				}
				if !bytes.Equal(buf0[2:n], buf1[:nr]) {
					t.Errorf("thread=%d/ sent != recv. nw=%d nr=%d\n", j, nw, nr)
				}
			}
			if log.V(2) {
				fmt.Printf("\tthread=%d/ done\n", j)
			}
		}(i)
	}
	wg.Wait()
	rest(3)
	checkFinishedLength(t)
}
