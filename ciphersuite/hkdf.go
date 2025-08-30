// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

// Portions of this file copied from some gist with unclear copyright.

package ciphersuite

import (
	"encoding/binary"
	"hash"
	"math"

	"github.com/hrissan/dtls/safecast"
)

// TODO - remove allocations

func Extract(hmacSalt hash.Hash, keymaterial []byte) (result Hash) {
	hmacSalt.Reset()
	hmacSalt.Write(keymaterial)
	result.SetSum(hmacSalt)
	return
}

func Expand(hmacSecret hash.Hash, info []byte, outlength int) []byte {
	n := (outlength + hmacSecret.Size() + 1) / hmacSecret.Size()
	var result []byte
	var T []byte
	for i := 1; i <= n; i++ {
		T = append(T, info...)
		T = append(T, byte(i)) // truncate
		hmacSecret.Reset()
		hmacSecret.Write(T)
		T = hmacSecret.Sum(T[:0])
		result = append(result, T...)
	}
	return result[:outlength]
}

func ExpandLabel(hmacSecret hash.Hash, label string, context []byte, length int) []byte {
	if length < 0 || length > math.MaxUint16 {
		panic("invalid expand label result length")
	}
	hkdflabel := make([]byte, 0, 128)
	hkdflabel = binary.BigEndian.AppendUint16(hkdflabel, uint16(length)) // safe due to check above
	hkdflabel = append(hkdflabel, safecast.Cast[byte](len(label)+6))
	hkdflabel = append(hkdflabel, "dtls13"...)
	hkdflabel = append(hkdflabel, label...)
	hkdflabel = append(hkdflabel, safecast.Cast[byte](len(context)))
	hkdflabel = append(hkdflabel, context...)
	return Expand(hmacSecret, hkdflabel, length)
}
