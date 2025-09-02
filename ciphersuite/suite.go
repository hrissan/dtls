// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import "hash"

type Suite interface {
	// when we protect or deprotect 3/4 of 2^exp packets, we ask for KeyUpdate
	// if peer does not respond quickly. and we reach 2^exp, we close connection for good
	ProtectionLimit() uint64
	// used for transcript hash for handshake. Unfortunately, allocates.
	NewHasher() hash.Hash
	// used for HKDF and such. Unfortunately, allocates.
	NewHMAC(key []byte) hash.Hash
	// Allocates only when cannot replace keys
	ResetSymmetricKeys(keys SymmetricKeys, secret Hash) SymmetricKeys
	EmptyHash() Hash
}

type ID uint16

const (
	// [rfc8446:4.5.3] AEAD Limits - 2^36 limit for 3 ciphers at the top
	TLS_AES_128_GCM_SHA256       ID = 0x1301
	TLS_AES_256_GCM_SHA384       ID = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 ID = 0x1303

	// ciphers below are not recommended to be implemented
	TLS_AES_128_CCM_SHA256   ID = 0x1304
	TLS_AES_128_CCM_8_SHA256 ID = 0x1305
)

var suite_TLS_AES_128_GCM_SHA256 Suite = &impl_TLS_AES_128_GCM_SHA256{}
var suite_TLS_AES_256_GCM_SHA384 Suite = &impl_TLS_AES_256_GCM_SHA384{}
var suite_TLS_CHACHA20_POLY1305_SHA256 Suite = &impl_TLS_CHACHA20_POLY1305_SHA256{}

func GetSuite(num ID) Suite {
	switch num {
	case TLS_AES_128_GCM_SHA256:
		return suite_TLS_AES_128_GCM_SHA256
	case TLS_AES_256_GCM_SHA384:
		return suite_TLS_AES_256_GCM_SHA384
	case TLS_CHACHA20_POLY1305_SHA256:
		return suite_TLS_CHACHA20_POLY1305_SHA256
	}
	panic("unsupported ciphersuite ID")
}
