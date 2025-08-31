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
	// [rfc8446:5.5] For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be encrypted
	return 1 << 24
}

func (s *impl_TLS_AES_128_GCM_SHA256) NewHasher() hash.Hash {
	return sha256.New()
}

func (s *impl_TLS_AES_128_GCM_SHA256) NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

func (s *impl_TLS_AES_128_GCM_SHA256) NewSymmetricKeys(secret Hash) SymmetricKeys {
	hmacSecret := s.NewHMAC(secret.GetValue())

	keys := &SymmetricKeysAES{}
	keys.fillWithSecret(hmacSecret, make([]byte, 16)) // on stack
	return keys
}

var emptySha256Hash Hash

func init() {
	ha := sha256.Sum256(nil)
	emptySha256Hash.SetValue(ha[:])
}

func (s *impl_TLS_AES_128_GCM_SHA256) EmptyHash() Hash {
	return emptySha256Hash
}
