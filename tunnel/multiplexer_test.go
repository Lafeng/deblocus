package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	log "github.com/spance/deblocus/golang/glog"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

var (
	cltAddr = "127.0.0.1:34567"
	svrAddr = "127.0.0.2:34568"
	dstAddr = "127.0.0.3:34569"
	client  *multiplexer
	server  *multiplexer
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.Set_output(true, "")
	log.Set_Verbose(1)
}

func startEmulation() {
	if client != nil {
		return
	}
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
				buf, e := ReadFullByLen(2, conn)
				if e != nil || len(buf) == 0 || (len(buf) == 1 && buf[0] == 0) {
					conn.Close()
					break
				} else {
					conn.Write(buf)
				}
			}
		}(dconn)
	}
}

func startServer() {
	ln, e := net.Listen("tcp", svrAddr)
	ThrowErr(e)
	defer ln.Close()
	server = NewServerMultiplexer()
	for {
		conn, e := ln.Accept()
		ThrowErr(e)
		go server.Listen(NewConn(conn.(*net.TCPConn), nil), nil, 0)
	}
}

func startClient(size int) {
	client = NewClientMultiplexer()
	for i := 0; i < size; i++ {
		conn, e := net.Dial("tcp", svrAddr)
		ThrowErr(e)
		go client.Listen(NewConn(conn.(*net.TCPConn), nil), nil, 0)
	}
	ln, e := net.Listen("tcp", cltAddr)
	ThrowErr(e)
	defer ln.Close()

	for {
		conn, e := ln.Accept()
		ThrowErr(e)
		go client.HandleRequest(conn, dstAddr)
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
	// assert server.registry.len==0
	assertLength(t, "server.registry", server.registry, 0)
	// assert client.registry.len==0
	assertLength(t, "client.registry", client.registry, 0)
	assertLength(t, "server.closed", server.closed, 0)
	assertLength(t, "client.closed", client.closed, 0)
}

func TestSingleRequest(t *testing.T) {
	startEmulation()
	conn, e := net.Dial("tcp", cltAddr)
	ThrowErr(e)
	rest(1)
	assertLength(t, "client.registry", client.registry, 1)
	buf0 := make([]byte, 0xffff)
	buf1 := make([]byte, 0xffff)
	for i := 0; i < 10; i++ {
		n := randomBuffer(buf0)
		binary.BigEndian.PutUint16(buf0, n-2)
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
			buf0 := make([]byte, 0xffff)
			buf1 := make([]byte, 0xffff)
			for i := 0; i < 99; i++ {
				n := randomBuffer(buf0)
				binary.BigEndian.PutUint16(buf0, n-2)
				nw, e := conn.Write(buf0[:n])
				ThrowErr(e)
				nr, e := io.ReadFull(conn, buf1[:n-2])
				ThrowErr(e)
				if log.V(3) {
					fmt.Printf("\tthread=%d send=%d recv=%d\n", j, nw, nr)
				}
				if !bytes.Equal(buf0[2:n], buf1[:nr]) {
					t.Errorf("thread=%d sent != recv. nw=%d nr=%d\n", j, nw, nr)
				}
			}
			conn.Close()
		}(i)
	}
	wg.Wait()
	rest(3)
	checkFinishedLength(t)
}
