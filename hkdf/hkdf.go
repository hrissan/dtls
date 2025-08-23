// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

// Portions of this file copied from some gist with unclear copyright.

package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"

	"github.com/hrissan/dtls/safecast"
)

// TODO - remove allocations
func HMAC(key, data []byte, h hash.Hash) []byte {
	mirror := hmac.New(sha256.New, key) // TODO - actually use h
	_, _ = mirror.Write(data)
	return mirror.Sum(nil)
}

func Extract(hasher hash.Hash, salt, keymaterial []byte) []byte {
	return HMAC(salt, keymaterial, hasher)
}

func Expand(hasher hash.Hash, keymaterial, info []byte, outlength int) []byte {
	n := (outlength + hasher.Size() + 1) / hasher.Size()
	result := []byte{}
	T := []byte{}
	for i := 1; i <= n; i++ {
		T = append(T, info...)
		T = append(T, byte(i)) // truncate
		T = HMAC(keymaterial, T, hasher)
		result = append(result, T...)
	}
	return result[:outlength]
}

func ExpandLabel(hasher hash.Hash, secret []byte, label string, context []byte, length int) []byte {
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
	return Expand(hasher, secret, hkdflabel, length)
}
