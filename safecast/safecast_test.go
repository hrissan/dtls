package safecast_test

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/hrissan/dtls/safecast"
)

func strconvAppend[Arg safecast.Integer](w []byte, arg Arg) []byte {
	switch v := any(arg).(type) {
	case int:
		return strconv.AppendInt(w, int64(v), 10)
	case int8:
		return strconv.AppendInt(w, int64(v), 10)
	case int16:
		return strconv.AppendInt(w, int64(v), 10)
	case int32:
		return strconv.AppendInt(w, int64(v), 10)
	case int64:
		return strconv.AppendInt(w, v, 10)
	case uint:
		return strconv.AppendUint(w, uint64(v), 10)
	case uint8:
		return strconv.AppendUint(w, uint64(v), 10)
	case uint16:
		return strconv.AppendUint(w, uint64(v), 10)
	case uint32:
		return strconv.AppendUint(w, uint64(v), 10)
	case uint64:
		return strconv.AppendUint(w, v, 10)
	case uintptr:
		return strconv.AppendUint(w, uint64(v), 10)
	case float32:
		return strconv.AppendFloat(w, float64(v), 'f', -1, 64)
	case float64:
		return strconv.AppendFloat(w, v, 'f', -1, 64)
	default:
		panic("must be never")
	}
}

func testCast[Result safecast.Integer, Arg safecast.Integer](t *testing.T, arg Arg) {
	var scratch1 [32]byte
	var scratch2 [32]byte
	_, err := safecast.TryCast[Result](arg)
	builtinCast := Result(arg)
	s1 := strconvAppend(scratch1[:0], arg)
	s2 := strconvAppend(scratch2[:0], builtinCast)
	good := string(s1) == string(s2)

	if (err == nil) != good {
		t.Errorf("%v %s -> %s %s\n", reflect.TypeOf(arg).String(), s1, reflect.TypeOf(builtinCast).String(), s2)
	}
}

func testCasts[Arg safecast.Integer](t *testing.T, arg Arg) {
	testCast[int](t, arg)
	testCast[int8](t, arg)
	testCast[int16](t, arg)
	testCast[int32](t, arg)
	testCast[int64](t, arg)
	testCast[uint](t, arg)
	testCast[uint8](t, arg)
	testCast[uint16](t, arg)
	testCast[uint32](t, arg)
	testCast[uint64](t, arg)
	testCast[uintptr](t, arg)
	//testCast[float32](t, arg)
	//testCast[float64](t, arg)
}

func testCastsFromInteger[Arg safecast.Integer](t *testing.T) {
	for highBits := uint64(0); highBits < 16; highBits++ {
		pattern1 := uint64((1<<64)-1) ^ (highBits << 60) // 00..00XXFF..FF
		pattern2 := highBits << 60                       // 00..00XX00..00
		pattern3 := uint64((1<<64)-1) ^ highBits         // FF..FFXX00..00
		for sh := 0; sh < 64; sh++ {
			testCasts(t, Arg(pattern1>>sh))
			testCasts(t, Arg(pattern2>>sh))
			testCasts(t, Arg(pattern3<<sh))
		}
	}
}

func TestPatterns(t *testing.T) {
	testCastsFromInteger[int](t)
	testCastsFromInteger[int8](t)
	testCastsFromInteger[int16](t)
	testCastsFromInteger[int32](t)
	testCastsFromInteger[int64](t)
	testCastsFromInteger[uint](t)
	testCastsFromInteger[uint8](t)
	testCastsFromInteger[uint16](t)
	testCastsFromInteger[uint32](t)
	testCastsFromInteger[uint64](t)
	testCastsFromInteger[uintptr](t)
	// testCastsFromFloat[float32](t)
	// testCastsFromFloat[float64](t)
}
