// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package circular_test

import (
	"testing"

	"github.com/hrissan/dtls/circular"
)

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
			if cb.Len() != 0 && cb.Front() != mirror[0] {
				t.FailNow()
			}
			for offset, value := range mirror {
				if cb.Index(offset) != value {
					t.FailNow()
				}
			}
			switch c {
			case 0:
				cb.PushBack(byte(i))
				mirror = append(mirror, byte(i))
			case 1:
				if cb.Len() != 0 {
					value1 := cb.PopFront()
					value2 := mirror[0]
					mirror = mirror[1:]
					if value1 != value2 {
						t.FailNow()
					}
				}
			case 2:
				cb.Clear()
				mirror = mirror[:0]
			default:
				cb.Reserve(int(c)) // widening
			}
		}
	})
}
