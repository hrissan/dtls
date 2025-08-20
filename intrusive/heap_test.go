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

func FuzzHeap(f *testing.F) {
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
				el := storage[int(c)%len(storage)]
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
				el := storage[int(c)%len(storage)]
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

func prepareHeap(size int) ([]testObject, *intrusive.IntrusiveHeap[testObject]) {
	objects := make([]testObject, size)
	for i := 0; i < size; i++ {
		objects[i].Value = i
	}
	heap := intrusive.NewIntrusiveHeap[testObject](func(i *testObject, i2 *testObject) bool {
		return i.Value < i2.Value
	}, size)
	return objects, heap
}

func BenchmarkInsertAsc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkInsertDesc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := b.N - 1; n >= 0; n-- {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkEraseAsc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkEraseDesc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}
