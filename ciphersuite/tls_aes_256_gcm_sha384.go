// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/hmac"
	"crypto/sha512"
	"hash"
)

type impl_TLS_AES_256_GCM_SHA384 struct {
}

func (s *impl_TLS_AES_256_GCM_SHA384) ProtectionLimit() uint64 {
	// [rfc8446:5.5] For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be encrypted
	return 1 << 24
}

func (s *impl_TLS_AES_256_GCM_SHA384) NewHasher() hash.Hash {
	return sha512.New384()
}

func (s *impl_TLS_AES_256_GCM_SHA384) NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

func (s *impl_TLS_AES_256_GCM_SHA384) NewSymmetricKeys(secret Hash) SymmetricKeys {
	hmacSecret := s.NewHMAC(secret.GetValue())

	keys := &SymmetricKeysAES{}
	keys.fillWithSecret(hmacSecret, make([]byte, 32)) // on stack
	return keys
}

var emptySha384Hash Hash

func init() {
	hasher := sha512.New384()
	emptySha384Hash.SetSum(hasher)
}

func (s *impl_TLS_AES_256_GCM_SHA384) EmptyHash() Hash {
	return emptySha384Hash
}
