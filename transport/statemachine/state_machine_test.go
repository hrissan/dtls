package statemachine

import "testing"

func testFun1(a uint) uint {
	return a + 1
}

func testFun2(a uint) uint {
	return a + 2
}

func BenchmarkAllocateGlobalFunc(b *testing.B) {
	// we wanted to see if it is efficient to use global functions
	// as a statemachine state
	b.ReportAllocs()
	f := testFun1
	g := testFun2
	var a uint
	for n := 0; n < b.N; n++ { // do 2 assignments per iteration
		a = f(a) + g(a)
		if n%2 == 0 {
			f = testFun1
		} else {
			f = testFun2
		}
		if n%3 == 0 {
			g = testFun1
		} else {
			g = testFun2
		}
	}
	benchmarkSideEffect = int(a) // side effect
}
