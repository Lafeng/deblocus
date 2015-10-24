package tunnel

import (
	"encoding/binary"
	"github.com/dchest/siphash"
	"math/rand"
	"testing"
	"time"
)

func Benchmark_randarray(b *testing.B) {
	size := 1024
	b.SetBytes(int64(size))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		randArray(size)
	}
}

func Benchmark_Siphash(b *testing.B) {
	size := 1024
	k1, k2 := uint64(rand.Int63()), uint64(rand.Int63())
	msg := randArray(size)
	b.SetBytes(int64(size))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		siphash.Hash(k1, k2, msg)
	}
}

// Test correctness of generating and verification
func TestDbcHello(tt *testing.T) {
	t := newTest(tt)
	tc := calculateTimeCounter(true)
	for i := 0; i < 1e5; i++ {
		pub := randArray(1 << 4)

		// generate
		data := pub[0]
		head := makeDbcHello(data, pub)
		len2 := byte(len(head) - DP_P2I)
		//tt.Logf("randBuf len=%d len2=%d", len(randBuf), len2)

		// verify
		ok, _data, _len2 := verifyDbcHello(head, pub, tc)
		t.Assert(ok).Fatalf("verifyDbcHead failed")
		t.Assert(len2 == _len2).Fatalf("expected len2=%d but _len2=%d", len2, _len2)
		t.Assert(data == _data).Fatalf("expected data=%d but _data=%d", data, _data)
	}
}

func timeErrorUnit(sp []byte, errors int) bool {
	_, _, hk := extractKeys(sp)
	// generate
	head := makeDbcHello(1, sp)
	// make error
	tc := uint64(time.Now().Unix()/TIME_STEP + int64(errors))
	errSum := siphash.Hash(hk, tc, head[:DP_LEN1])
	binary.BigEndian.PutUint64(head[DP_LEN1:], errSum)
	// verify
	tcArr := calculateTimeCounter(true)
	ok, _, _ := verifyDbcHello(head, sp, tcArr)
	return ok
}

func TestDbcHelloTimeError(tt *testing.T) {
	t := newTest(tt)
	sp := randArray(1 << 10)

	for i, j := 0, 0; i <= 9; i++ {
		// -i, +i, -2i, +2i....
		if i&1 == 1 {
			j = -i
		} else {
			j = i
		}
		// expected PASS if i <= TIME_ERROR
		// expected DENY if i >  TIME_ERROR
		t.Assert(i <= TIME_ERROR == timeErrorUnit(sp, j)).Fatalf("%+d failed", j)
	}
}

//
// ---------------------------------------------
//

type test struct {
	testing.TB
}

func newTest(tt testing.TB) *test {
	return &test{tt}
}

func (t *test) Assert(cond bool) testing.TB {
	if cond {
		return t
	} else {
		return t.TB
	}
}

func (t *test) Error(args ...interface{})                 {}
func (t *test) Errorf(format string, args ...interface{}) {}
func (t *test) Fail()                                     {}
func (t *test) FailNow()                                  {}
func (t *test) Failed() bool                              { return t.TB.Failed() }
func (t *test) Fatal(args ...interface{})                 {}
func (t *test) Fatalf(format string, args ...interface{}) {}
func (t *test) Log(args ...interface{})                   {}
func (t *test) Logf(format string, args ...interface{})   {}
func (t *test) Skip(args ...interface{})                  {}
func (t *test) SkipNow()                                  {}
func (t *test) Skipf(format string, args ...interface{})  {}
func (t *test) Skipped() bool                             { return t.TB.Skipped() }
