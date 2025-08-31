// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
	"golang.org/x/crypto/chacha20poly1305"
)

type SymmetricKeys struct {
	SN      cipher.Block // 16 interface + 240 aes half + (240 aes half we do not need). Can be removed with unencrypted sequence numbers extension
	Write   cipher.AEAD  // 16 interface + 16 interface inside + 16 (counters) + 240 aes half + (240 aes half we do not need)
	WriteIV [12]byte
}

func (keys *SymmetricKeys) EncryptSequenceNumbers(seqNum []byte, cipherText []byte) error {
	var mask [32]byte // Some space good for many ciphers, TODO - check constant mush earlier
	if len(cipherText) < keys.SN.BlockSize() {
		return dtlserrors.WarnCipherTextTooShortForSNDecryption
	}
	keys.SN.Encrypt(mask[:], cipherText)
	if len(seqNum) == 1 {
		seqNum[0] ^= mask[0]
		return nil
	}
	if len(seqNum) == 2 {
		seqNum[0] ^= mask[0]
		seqNum[1] ^= mask[1]
		return nil
	}
	panic("seqNum must have 1 or 2 bytes")
}

// panic if len(iv) is < 8
func FillIVSequence(iv []byte, seq uint64) {
	maskBytes := iv[len(iv)-8:]
	mask := binary.BigEndian.Uint64(maskBytes)
	binary.BigEndian.PutUint64(maskBytes, seq^mask)
}

func NewAesCipher(key []byte) cipher.Block {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher fails " + err.Error())
	}
	return c
}

func NewChacha20Poly1305(key []byte) cipher.AEAD {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("chacha20poly1305.NewCipher fails " + err.Error())
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

// contentType is the first non-zero byte from the end
func findPaddingOffsetContentType(data []byte) (paddingOffset int, contentType byte) {
	offset := len(data)
	for ; offset > 16; offset -= 16 { // poor man's SIMD
		slice := data[offset-16 : offset]
		val1 := binary.LittleEndian.Uint64(slice)
		val2 := binary.LittleEndian.Uint64(slice[8:])
		if (val1 | val2) != 0 {
			break
		}
	}
	for ; offset > 0; offset-- {
		b := data[offset-1]
		if b != 0 {
			return offset - 1, b
		}
	}
	return -1, 0
}

// Warning - decrypts in place, seqNumData and body can be garbage after unsuccessfull decryption
func (keys *SymmetricKeys) Deprotect(hdr record.Ciphertext, encryptSN bool, expectedSN uint64) (decrypted []byte, seq uint64, contentType byte, err error) {
	if encryptSN {
		if err := keys.EncryptSequenceNumbers(hdr.SeqNum, hdr.Body); err != nil {
			return nil, 0, 0, err
		}
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
		// TODO - send alert
		return nil, seq, 0, dtlserrors.ErrCipherTextAllZeroPadding
	}
	return decrypted[:paddingOffset], seq, contentType, nil
}
