// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
)

const symmetricKeysAESSealSize = 16

type SymmetricKeysAES struct {
	SN      cipher.Block // 16 interface + 240 aes half + (240 aes half we do not need). Can be removed with unencrypted sequence numbers extension
	Write   cipher.AEAD  // 16 interface + 16 interface inside + 16 (counters) + 240 aes half + (240 aes half we do not need)
	WriteIV [12]byte
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

func (keys *SymmetricKeysAES) EncryptSeqMask(cipherText []byte) ([2]byte, error) {
	var mask [aes.BlockSize]byte
	if len(cipherText) < keys.SN.BlockSize() {
		return [2]byte{}, dtlserrors.WarnCipherTextTooShortForSNDecryption
	}
	keys.SN.Encrypt(mask[:], cipherText)
	return [2]byte(mask[0:2]), nil
}

func (keys *SymmetricKeysAES) RecordOverhead() (AEADSealSize int, SNBlockSize int) {
	return symmetricKeysAESSealSize, aes.BlockSize
}

func (keys *SymmetricKeysAES) AEADEncrypt(seq uint64, datagramLeft []byte, hdrSize int, insideSize int) {
	iv := keys.WriteIV
	FillIVSequence(iv[:], seq)

	encrypted := keys.Write.Seal(datagramLeft[hdrSize:hdrSize], iv[:], datagramLeft[hdrSize:hdrSize+insideSize], datagramLeft[:hdrSize])
	if &encrypted[0] != &datagramLeft[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagramLeft[hdrSize:hdrSize+insideSize+symmetricKeysAESSealSize]) {
		panic("gcm.Seal length mismatch")
	}
}

func (keys *SymmetricKeysAES) Deprotect(hdr record.Ciphertext, encryptSN bool, expectedSN uint64) (decrypted []byte, seq uint64, contentType byte, err error) {
	if encryptSN {
		mask, err := keys.EncryptSeqMask(hdr.Body)
		if err != nil {
			return nil, 0, 0, err
		}
		encryptSeq(hdr.SeqNum, mask)
	}
	gcm := keys.Write
	iv := keys.WriteIV // copy, otherwise disaster
	decryptedSeqData, seq := hdr.ClosestSequenceNumber(hdr.SeqNum, expectedSN)
	fmt.Printf("decrypted SN: %d, closest: %d\n", decryptedSeqData, seq)

	FillIVSequence(iv[:], seq)
	decrypted, err = gcm.Open(hdr.Body[:0], iv[:], hdr.Body, hdr.Header)
	if err != nil {
		return nil, seq, 0, dtlserrors.WarnAEADDeprotectionFailed
	}
	paddingOffset, contentType := findPaddingOffsetContentType(decrypted) // [rfc8446:5.4]
	if paddingOffset < 0 {
		return nil, seq, 0, dtlserrors.ErrCipherTextAllZeroPadding
	}
	return decrypted[:paddingOffset], seq, contentType, nil
}
