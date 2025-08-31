// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"hash"

	"github.com/hrissan/dtls/constants"
)

// we like static storage, so we do almost no allocations
type Hash struct {
	data [constants.MaxHashLength]byte
	size int
}

func (h *Hash) GetValue() []byte {
	return h.data[0:h.size]
}

func (h *Hash) Len() int {
	return h.size
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
	h.size = len(da)
}

func (h *Hash) SetZero(size int) {
	if size > len(h.data) {
		panic("zero hash length exceeds hash storage size")
	}
	*h = Hash{size: size}
}

func (h *Hash) SetValue(data []byte) {
	if len(data) > len(h.data) {
		panic("hash length exceeds hash storage size")
	}
	*h = Hash{size: len(data)} // clear data, so objects are equal by built-int operator
	copy(h.data[:], data)
}
