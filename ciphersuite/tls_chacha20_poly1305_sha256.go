// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"math"
)

type impl_TLS_CHACHA20_POLY1305_SHA256 struct {
}

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) ProtectionLimit() uint64 {
	// [rfc8446:5.5] For ChaCha20/Poly1305, the record sequence number would wrap before the safety limit is reached
	return math.MaxUint64
}

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) NewHasher() hash.Hash {
	return sha256.New()
}

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) ResetSymmetricKeys(keys SymmetricKeys, secret Hash) SymmetricKeys {
	ourKeys, _ := keys.(*SymmetricKeysChaCha20Poly1305)
	if ourKeys == nil {
		ourKeys = &SymmetricKeysChaCha20Poly1305{}
	}

	const keySize = 32

	hmacSecret := s.NewHMAC(secret.GetValue())

	var writeKey [keySize]byte
	HKDFExpandLabel(writeKey[:], hmacSecret, "key", nil)
	ourKeys.Write = NewChacha20Poly1305(writeKey[:])

	HKDFExpandLabel(ourKeys.SNKey[:], hmacSecret, "sn", nil)

	HKDFExpandLabel(ourKeys.WriteIV[:], hmacSecret, "iv", nil)
	return ourKeys
}

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) EmptyHash() Hash {
	return emptySha256Hash
}
