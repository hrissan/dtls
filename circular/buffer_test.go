// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package circular_test

import (
	"math/rand/v2"
	"testing"

	"github.com/hrissan/dtls/circular"
)

var benchmarkSideEffect int

func BenchmarkDiv9(b *testing.B) {
	dividend := 12345678912341234 + rand.IntN(100)
	value := benchmarkSideEffect
	for i := 0; i < b.N; i++ {
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
	}
	benchmarkSideEffect = value
}

func BenchmarkDiv129(b *testing.B) {
	const dividend = 129
	value := benchmarkSideEffect
	for i := 0; i < b.N; i++ {
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
		value += (^value) / dividend
	}
	benchmarkSideEffect = value
}

func BenchmarkDiv128(b *testing.B) {
	const dividend = 128
	value := benchmarkSideEffect
	for i := 0; i < b.N; i++ {
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
		value += (^value + 191) / dividend
	}
	benchmarkSideEffect = value
}

func BenchmarkDiv128U(b *testing.B) {
	const dividend = 128
	value := benchmarkSideEffect
	for i := 0; i < b.N; i++ {
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
		value += int(uint(^value+191) / dividend)
	}
	benchmarkSideEffect = value
}

func BenchmarkDiv128Shift(b *testing.B) {
	value := benchmarkSideEffect
	for i := 0; i < b.N; i++ {
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
		value += (^value + 191) >> 7
	}
	benchmarkSideEffect = value
}

func FuzzCircularBuffer(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		cb := circular.Buffer[byte]{}
		var mirror []byte
		for i, c := range commands {
			if cb.Len() != len(mirror) {
				t.FailNow()
			}
			a, b := cb.Slices()
			if string(append(append([]byte{}, a...), b...)) != string(mirror) {
				t.FailNow()
			}
			if cb.Len() != 0 && (cb.Front() != mirror[0] || cb.Back() != mirror[len(mirror)-1]) {
				t.FailNow()
			}
			for offset, value := range mirror {
				if cb.Index(offset) != value {
					t.FailNow()
				}
			}
			switch c {
			case 0:
				cb.Clear()
				mirror = mirror[:0]
			case 1:
				cb.PushBack(byte(i))
				mirror = append(mirror, byte(i))
			case 2:
				cb.PushFront(byte(i))
				mirror = append([]byte{byte(i)}, mirror...)
			case 3:
				if cb.Len() != 0 {
					value1 := cb.PopFront()
					value2 := mirror[0]
					mirror = mirror[1:]
					if value1 != value2 {
						t.FailNow()
					}
				}
			case 4:
				if cb.Len() != 0 {
					value1 := cb.PopBack()
					value2 := mirror[len(mirror)-1]
					mirror = mirror[:len(mirror)-1]
					if value1 != value2 {
						t.FailNow()
					}
				}
			default:
				cb.Reserve(int(c)) // widening
			}
		}
	})
}
