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

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) NewSymmetricKeys(secret Hash) SymmetricKeys {
	const keySize = 32

	keys := &SymmetricKeysAES{}
	hmacSecret := s.NewHMAC(secret.GetValue())
	var writeKey [keySize]byte
	HKDFExpandLabel(writeKey[:], hmacSecret, "key", nil)
	HKDFExpandLabel(keys.WriteIV[:], hmacSecret, "iv", nil)
	var snKey [keySize]byte
	HKDFExpandLabel(snKey[:], hmacSecret, "sn", nil)

	keys.Write = NewGCMCipher(NewAesCipher(writeKey[:]))
	keys.SN = NewAesCipher(snKey[:])
	return keys
}

/*func (s *impl_TLS_CHACHA20_POLY1305_SHA256) ComputeSymmetricKeys(keys *SymmetricKeys, secret Hash) {
	const keySize = 32
	hmacSecret := s.NewHMAC(secret.GetValue())
	var writeKey [keySize]byte
	HKDFExpandLabel(writeKey[:], hmacSecret, "key", nil)
	HKDFExpandLabel(keys.WriteIV[:], hmacSecret, "iv", nil)
	var snKey [keySize]byte
	HKDFExpandLabel(snKey[:], hmacSecret, "sn", nil)

	keys.Write = NewChacha20Poly1305(writeKey[:])
	//sn, _ := chacha20.NewUnauthenticatedCipher(nil, nil)
	//keys.SN = sn
}*/

func (s *impl_TLS_CHACHA20_POLY1305_SHA256) EmptyHash() Hash {
	return emptySha256Hash
}
