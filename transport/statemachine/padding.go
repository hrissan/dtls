// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import "encoding/binary"

// contentType is the first non-zero byte from the end
func findPaddingOffsetContentType(data []byte) (paddingOffset int, contentType byte) {
	offset := len(data)
	for ; offset > 16; offset -= 16 { // poor man's SIMD
		slice := data[offset-16 : offset]
		val1 := binary.LittleEndian.Uint64(slice)
		val2 := binary.LittleEndian.Uint64(slice[8:])
		if (val1 | val2) != 0 {
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
