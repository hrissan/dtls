// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package intrusive_test

import (
	"cmp"
	"slices"
	"testing"

	"github.com/hrissan/dtls/intrusive"
)

// cpu: 13th Gen Intel(R) Core(TM) i7-1360P
// BenchmarkInsertAsc-16     	121955037	        13.43 ns/op	      32 B/op	       0 allocs/op
// BenchmarkInsertDesc-16    	19573603	        73.57 ns/op	      32 B/op	       0 allocs/op
// BenchmarkEraseAsc-16      	 8083260	       176.0 ns/op	       0 B/op	       0 allocs/op
// BenchmarkEraseDesc-16     	397347442	         3.111 ns/op	       0 B/op	       0 allocs/op

type testObject struct {
	Value int

	HeapIndex int
}

func testObjectPred(a *testObject, b *testObject) bool {
	return a.Value < b.Value
}

func FuzzHeapSimple(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		var storage []*testObject
		for i := 0; i < 20; i++ {
			storage = append(storage, &testObject{Value: i})
		}

		heap := intrusive.NewIntrusiveHeap[testObject](testObjectPred, 0)
		var mirror []*testObject
		for _, c := range commands {
			if heap.Len() != len(mirror) {
				t.FailNow()
			}
			if heap.Len() != 0 {
				slices.SortFunc(mirror, func(a, b *testObject) int {
					return cmp.Compare(a.Value, b.Value)
				})
				if heap.Front() != mirror[0] {
					t.FailNow()
				}
			}
			switch {
			case c == 0:
				if len(mirror) != 0 {
					// checked equality above
					heap.PopFront()
					mirror = mirror[1:]
				}
			case c < 128:
				el := storage[int(c)%len(storage)] // widening
				mirrorIndex := -1
				for i, m := range mirror {
					if el == m {
						mirrorIndex = i
						break
					}
				}
				inserted := heap.Insert(el, &el.HeapIndex)
				if inserted {
					if mirrorIndex != -1 {
						t.FailNow()
					}
					mirror = append(mirror, el)
				} else {
					if mirrorIndex == -1 {
						t.FailNow()
					}
				}
			default:
				el := storage[int(c)%len(storage)] // widening
				mirrorIndex := -1
				for i, m := range mirror {
					if el == m {
						mirrorIndex = i
						break
					}
				}
				erased := heap.Erase(el, &el.HeapIndex)
				if erased {
					if mirrorIndex == -1 {
						t.FailNow()
					}
					mirror = append(mirror[:mirrorIndex], mirror[mirrorIndex+1:]...)
				} else {
					if mirrorIndex != -1 {
						t.FailNow()
					}
				}
			}
		}
	})
}
