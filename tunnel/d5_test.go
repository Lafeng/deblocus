package tunnel

import (
	"encoding/binary"
	"github.com/dchest/siphash"
	"math/rand"
	"testing"
	"time"
)

func TestRandFilling(t *testing.T) {
	t1 := time.Now()
	var count int = 1e3
	for i := 0; i < count; i++ {
		_ = randArray(1 << 20)
	}
	tu := time.Since(t1).Nanoseconds() / 1e6
	t.Logf("total=%dms speed=%.2fm/s", tu, float64(count*1e3)/float64(tu))
}

func TestSiphash(t *testing.T) {
	k1, k2 := uint64(rand.Int63()), uint64(rand.Int63())
	msg := randArray(1 << 9) // 512B
	var loop int = 6e6
	t1 := time.Now()
	for i := 0; i < loop; i++ {
		siphash.Hash(k1, k2, msg)
	}
	tu := time.Since(t1).Nanoseconds() / 1e6
	t.Logf("tu=%dms throughput=%.2fm", tu, float64(loop*len(msg))/float64(1<<20))
}

func TestRandHead(tt *testing.T) {
	t := newTest(tt)
	for i := 0; i < 1e3; i++ {
		pub := randArray(1 << 10)

		// generate
		data := int(pub[0])
		randBuf := makeRandHead(byte(data), pub)
		len2 := len(randBuf) - DP_P2I
		//t.Logf("randBuf len=%d len2=%d", len(randBuf), len2)

		// verify
		ok, _data, _len2 := verifyRandHead(randBuf, pub)
		t.Assert(ok).Fatalf("verifyRandHead failed")
		t.Assert(data == _data).Fatalf("expected data=%d but _data=%d", data, _data)
		t.Assert(len2 == _len2).Fatalf("expected len2=%d but _len2=%d", len2, _len2)
	}
}

func timeErrorUnit(sp []byte, errors int) bool {
	_, _, hk := extractKeys(sp)
	// generate
	randBuf := makeRandHead(1, sp)
	// make error
	tc := uint64(time.Now().Unix()/TIME_STEP + int64(errors))
	errSum := siphash.Hash(hk, tc, randBuf[:DP_LEN1])
	binary.BigEndian.PutUint64(randBuf[DP_LEN1:], errSum)
	// verify
	ok, _, _ := verifyRandHead(randBuf, sp)
	return ok
}

func TestRandHeadTimeError(tt *testing.T) {
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
