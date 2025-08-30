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

func HKDFExtract(hmacSalt hash.Hash, keymaterial []byte) (result Hash) {
	hmacSalt.Reset()
	hmacSalt.Write(keymaterial)
	result.SetSum(hmacSalt)
	return
}

func HKDFExpand(dst []byte, hmacSecret hash.Hash, info []byte) {
	offset := 0
	hmacSecret.Reset()
	var ha Hash
	for i := 1; offset < len(dst); i++ {
		hmacSecret.Write(info)
		hmacSecret.Write([]byte{byte(i)}) // truncate
		ha.SetSum(hmacSecret)
		offset += copy(dst[offset:], ha.GetValue())
		hmacSecret.Reset()
		hmacSecret.Write(ha.GetValue())
	}
}

func HKDFExpandLabel(dst []byte, hmacSecret hash.Hash, label string, context []byte) {
	if len(dst) > math.MaxUint16 {
		panic("invalid expand label result length")
	}
	hkdflabel := make([]byte, 0, 128)
	hkdflabel = binary.BigEndian.AppendUint16(hkdflabel, uint16(len(dst))) // safe due to check above
	hkdflabel = append(hkdflabel, safecast.Cast[byte](len(label)+6))
	hkdflabel = append(hkdflabel, "dtls13"...)
	hkdflabel = append(hkdflabel, label...)
	hkdflabel = append(hkdflabel, safecast.Cast[byte](len(context)))
	hkdflabel = append(hkdflabel, context...)
	HKDFExpand(dst, hmacSecret, hkdflabel)
}
