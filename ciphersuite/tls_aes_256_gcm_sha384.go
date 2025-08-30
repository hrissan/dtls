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
	return 1 << 36
}

func (s *impl_TLS_AES_256_GCM_SHA384) NewHasher() hash.Hash {
	return sha512.New384()
}

func (s *impl_TLS_AES_256_GCM_SHA384) NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

func (s *impl_TLS_AES_256_GCM_SHA384) ComputeSymmetricKeys(keys *SymmetricKeys, secret Hash) {
	const keySize = 32
	hmacSecret := s.NewHMAC(secret.GetValue())
	var writeKey [keySize]byte
	HKDFExpandLabel(writeKey[:], hmacSecret, "key", nil)
	HKDFExpandLabel(keys.WriteIV[:], hmacSecret, "iv", nil)
	var snKey [keySize]byte
	HKDFExpandLabel(snKey[:], hmacSecret, "sn", nil)

	keys.Write = NewGCMCipher(NewAesCipher(writeKey[:]))
	keys.SN = NewAesCipher(snKey[:])
}

var emptySha384Hash Hash

func init() {
	hasher := sha512.New384()
	emptySha384Hash.SetSum(hasher)
}

func (s *impl_TLS_AES_256_GCM_SHA384) EmptyHash() Hash {
	return emptySha384Hash
}
