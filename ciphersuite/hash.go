// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"hash"
)

const MaxHashLength = 48

// We want fixed-size storage for hashes, as we want to do as few allocations as possible
// If we ever need very large hashes, we may want to start using allocated storage.
type Hash struct {
	data [MaxHashLength]byte
	size byte
}

func (h *Hash) GetValue() []byte {
	return h.data[0:h.size]
}

func (h *Hash) Len() int {
	return int(h.size) // widening
}

func (h *Hash) Cap() int {
	return len(h.data)
}

func (h *Hash) SetSum(hasher hash.Hash) {
	*h = Hash{} // clear data, so objects are equal by built-int operator
	da := hasher.Sum(h.data[:0])
	if len(da) > len(h.data) {
		panic("hasher length exceeds hash storage size")
	}
	h.size = byte(len(da)) // safe due to check above
}

func (h *Hash) SetZero(size int) {
	if size > len(h.data) {
		panic("zero hash length exceeds hash storage size")
	}
	*h = Hash{size: byte(size)} // safe due to check above
}

func (h *Hash) SetValue(data []byte) {
	if len(data) > len(h.data) {
		panic("hash length exceeds hash storage size")
	}
	// clear data, so objects are equal by built-int operator
	*h = Hash{size: byte(len(data))} // safe due to check above
	copy(h.data[:], data)
}
