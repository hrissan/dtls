package intrusive_test

import (
	"cmp"
	"slices"
	"testing"

	"github.com/hrissan/tinydtls/intrusive"
)

type testObject struct {
	Value int

	HeapIndex int
}

func testObjectPred(a *testObject, b *testObject) bool {
	return a.Value > b.Value
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
					storage = append(storage, mirror[0])
					// checked equality above
					heap.PopFront()
					mirror = mirror[1:]
				}
			case c == 1:
				if len(storage) != 0 {
					el := storage[int(c)%len(storage)]
					heap.Erase(el, &el.HeapIndex) // NOP
				}
			case c < 128:
				if len(storage) != 0 {
					ind := int(c) % len(storage)
					el := storage[ind]
					storage = append(storage[:ind], storage[ind+1:]...)
					heap.Insert(el, &el.HeapIndex)
					mirror = append(mirror, el)
				}
			default:
				if len(mirror) != 0 {
					ind := int(c) % len(mirror)
					el := mirror[ind]
					heap.Erase(el, &el.HeapIndex)
					mirror = append(mirror[:ind], mirror[ind+1:]...)
				}
			}
		}
	})
}
