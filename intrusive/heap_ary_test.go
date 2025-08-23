// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package intrusive_test

import (
	"cmp"
	"slices"
	"testing"

	"github.com/hrissan/dtls/intrusive"
)

func FuzzHeapAry(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		var storage []*testObject
		for i := 0; i < 20; i++ {
			storage = append(storage, &testObject{Value: i})
		}

		heap := intrusive.NewIntrusiveHeapAry[testObject](testObjectPred, 0)
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
