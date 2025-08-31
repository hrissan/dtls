// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
)

const symmetricKeysAESSealSize = 16

type SymmetricKeysAES struct {
	SN      cipher.Block
	Write   cipher.AEAD
	WriteIV [12]byte
}

func (keys *SymmetricKeysAES) RecordOverhead() (AEADSealSize int, MinCiphertextSize int) {
	return symmetricKeysAESSealSize, aes.BlockSize
}

func (keys *SymmetricKeysAES) EncryptSeqMask(ciphertext []byte) ([2]byte, error) {
	var mask [aes.BlockSize]byte
	if len(ciphertext) < keys.SN.BlockSize() {
		return [2]byte{}, dtlserrors.WarnCipherTextTooShortForSNDecryption
	}
	keys.SN.Encrypt(mask[:], ciphertext)
	return [2]byte(mask[0:2]), nil
}

func (keys *SymmetricKeysAES) AEADEncrypt(seq uint64, datagramLeft []byte, hdrSize int, plaintextSize int) {
	iv := keys.WriteIV
	FillIVSequence(iv[:], seq)

	additionalData := datagramLeft[:hdrSize]
	plaintext := datagramLeft[hdrSize : hdrSize+plaintextSize]

	encrypted := keys.Write.Seal(datagramLeft[hdrSize:hdrSize], iv[:], plaintext, additionalData)
	if &encrypted[0] != &datagramLeft[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(plaintext)+symmetricKeysAESSealSize {
		panic("gcm.Seal length mismatch")
	}
}

func (keys *SymmetricKeysAES) AEADDecrypt(rec record.Encrypted, seq uint64) (plaintextSize int, err error) {
	gcm := keys.Write
	iv := keys.WriteIV // copy, otherwise disaster

	FillIVSequence(iv[:], seq)
	decrypted, err := gcm.Open(rec.Ciphertext[:0], iv[:], rec.Ciphertext, rec.Header)
	if err != nil {
		return 0, dtlserrors.WarnAEADDeprotectionFailed
	}
	if &decrypted[0] != &rec.Ciphertext[0] {
		panic("gcm.Open reallocated datagram storage")
	}
	if len(decrypted)+symmetricKeysAESSealSize != len(rec.Ciphertext) {
		panic("unexpected decrypted body size")
	}
	return len(decrypted), nil
}

func NewAesCipher(key []byte) cipher.Block {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher fails " + err.Error())
	}
	return c
}

func NewGCMCipher(block cipher.Block) cipher.AEAD {
	c, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher.NewGCM fails " + err.Error())
	}
	return c
}

func (keys *SymmetricKeysAES) fillWithSecret(hmacSecret hash.Hash, keyStorage []byte) {
	// write key
	HKDFExpandLabel(keyStorage[:], hmacSecret, "key", nil)
	keys.Write = NewGCMCipher(NewAesCipher(keyStorage[:]))

	// sn key
	HKDFExpandLabel(keyStorage[:], hmacSecret, "sn", nil)
	keys.SN = NewAesCipher(keyStorage[:])

	HKDFExpandLabel(keys.WriteIV[:], hmacSecret, "iv", nil)
}
