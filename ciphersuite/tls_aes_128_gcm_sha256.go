// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

type impl_TLS_AES_128_GCM_SHA256 struct {
}

func (s *impl_TLS_AES_128_GCM_SHA256) ProtectionLimit() uint64 {
	return 1 << 36
}

func (s *impl_TLS_AES_128_GCM_SHA256) NewHasher() hash.Hash {
	return sha256.New()
}

func (s *impl_TLS_AES_128_GCM_SHA256) NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

func (s *impl_TLS_AES_128_GCM_SHA256) ComputeSymmetricKeys(k *SymmetricKeys, secret []byte) {
	// TODO
}
