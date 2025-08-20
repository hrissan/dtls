package keys

import (
	"testing"
)

//BenchmarkPadding_1X-16        	  259910	      4466 ns/op
//BenchmarkPadding_8X-16        	  872008	      1258 ns/op
//BenchmarkPadding_16X-16       	 1720522	       698.2 ns/op
//BenchmarkPadding_Unsafe16X-16    	 2797153	       428.0 ns/op
//BenchmarkPadding_Unsafe32X-16    	 5298525	       228.9 ns/op

// contentType is the first non-zero byte from the end
func findPaddingOffsetContentType1X(data []byte) (paddingOffset int, contentType byte) {
	offset := len(data)
	for ; offset > 0; offset-- {
		b := data[offset-1]
		if b != 0 {
			return offset - 1, b
		}
	}
	return -1, 0
}

/*
// Commented, because we do not want dependency on unsafe.
// BTW our code can be declared safe only if we prove it contains no race conditions,
// which is hard to impossible (but we'll try).

func findPaddingOffsetContentTypeUnsafe32(data []byte) (paddingOffset int, contentType byte) {
	offset := len(data)

	ptr := unsafe.Pointer(&data[0])
	for ; offset > 32; offset -= 32 { // poor man's SIMD
		val1 := *(*uint64)(unsafe.Add(ptr, offset-32))
		val2 := *(*uint64)(unsafe.Add(ptr, offset-24))
		val3 := *(*uint64)(unsafe.Add(ptr, offset-16))
		val4 := *(*uint64)(unsafe.Add(ptr, offset-8))
		if (val1 | val2 | val3 | val4) != 0 {
			break
		}
	}
	for ; offset > 0; offset-- {
		b := data[offset-1]
		if b != 0 {
			return offset - 1, b
		}
	}
	return -1, 0
}
*/

var benchmarkSideEffect = 0

func BenchmarkPadding_1X(b *testing.B) {
	var record [16384]byte
	record[0] = 1
	for i := 0; i < b.N; i++ {
		offset, contentType := findPaddingOffsetContentType1X(record[:16384-i%16])
		if contentType != 0 {
			benchmarkSideEffect += offset
		}
	}
}

func BenchmarkPadding_16X(b *testing.B) {
	var record [16384]byte
	record[0] = 1
	for i := 0; i < b.N; i++ {
		offset, contentType := findPaddingOffsetContentType(record[:16384-i%16])
		if contentType != 0 {
			benchmarkSideEffect += offset
		}
	}
}
