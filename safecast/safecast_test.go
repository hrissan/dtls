package safecast

import (
	"testing"
)

func testCast[Result Integer, Arg Integer](t *testing.T, arg Arg) {
	var scratch1 [32]byte
	var scratch2 [32]byte
	_, err := TryCast[Result](arg)
	s1 := Append(scratch1[:], arg, 10)
	s2 := Append(scratch2[:], Result(arg), 10)
	good := string(s1) == string(s2)

	if (err == nil) != good {
		t.Errorf("result of string cast different to safecast")
	}
}

func testCasts[Arg Integer](t *testing.T, arg Arg) {
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
}

func FuzzCast(f *testing.F) {
	f.Fuzz(func(t *testing.T, arg1 int64, arg2 uint64, arg3 int8, arg4 uint8) {
		testCasts(t, arg1)
		testCasts(t, arg2)
		testCasts(t, arg3)
		testCasts(t, arg4)
	})
}
