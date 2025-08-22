// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package replay

import (
	"bytes"
	"testing"
)

const assemblerMessageLength = 32 // no benefits of larger values

func getMirrorFragmentFromOffset(m []byte, fromOffset uint32) (offset uint32, length uint32) {
	if fromOffset >= uint32(len(m)) {
		return 0, 0
	}
	indZero := bytes.IndexByte(m[fromOffset:], 0)
	if indZero < 0 {
		return 0, 0
	}
	offset = fromOffset + uint32(indZero)
	indOne := bytes.IndexByte(m[offset:], 1)
	if indOne < 0 {
		return offset, uint32(len(m)) - offset
	}
	return offset, uint32(indOne)
}

func FuzzAssembler(f *testing.F) {
	f.Fuzz(func(t *testing.T, commands []byte) {
		cb := Assembler{}
		cb.ResetToFull(assemblerMessageLength)
		assemblerMirrorCopy := make([]byte, assemblerMessageLength)
		mirror := make([]byte, assemblerMessageLength)
		for i := 0; i+1 < len(commands); i += 2 {
			start := uint32(commands[i])
			length := uint32(commands[i+1])
			cb.checkInvariants()
			cb.fillMirror(assemblerMirrorCopy)
			if string(assemblerMirrorCopy) != string(mirror) {
				t.FailNow()
			}
			for j := 0; j < assemblerMessageLength+1; j++ {
				segOff, segLen := cb.GetFragmentFromOffset(uint32(j))
				segOff2, segLen2 := getMirrorFragmentFromOffset(mirror, uint32(j))
				if segOff != segOff2 || segLen != segLen2 {
					t.FailNow()
				}
			}
			shouldAck, changed := cb.AddFragment(start, length)
			changed2 := false
			if shouldAck {
				for j := start; j < start+length; j++ {
					if j < uint32(len(mirror)) && mirror[j] != 1 {
						mirror[j] = 1
						changed2 = true
					}
				}
			}
			if changed != changed2 {
				t.FailNow()
			}
		}
	})
}
