// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/hrissan/dtls/record"
	"golang.org/x/crypto/chacha20poly1305"
)

type SymmetricKeys interface {
	// 1 or 2 bytes of mask actually used, depending on 8-bit or 16-bit sequence number fornat
	EncryptSequenceNumbersMask(cipherText []byte) ([2]byte, error)

	// datagramLeft is space to the end of datagram
	// Reserves space for header and padding, returns ok and insideBody to write application data into,
	// or (if even 0-byte application data will not fit), returns !ok.
	// Caller should check if his data fits into insideBody, put it there.
	PrepareProtect(datagramLeft []byte, use8BitSeq bool) (hdrSize int, insideBody []byte, ok bool)

	// Pass the same datagramLeft, returned hdrSize, and pass insideSize, how many data copied into insideBody
	Protect(rn record.Number, encryptSN bool, recordType byte, datagramLeft []byte, hdrSize int, insideSize int) (recordSize int)

	// Warning - decrypts in place, seqNumData and body can be garbage after unsuccessfull decryption
	Deprotect(hdr record.Ciphertext, encryptSN bool, expectedSN uint64) (decrypted []byte, seq uint64, contentType byte, err error)
}

func encryptSequenceNumbers(seqNum []byte, mask [2]byte) {
	if len(seqNum) == 1 {
		seqNum[0] ^= mask[0]
		return
	}
	if len(seqNum) == 2 {
		seqNum[0] ^= mask[0]
		seqNum[1] ^= mask[1]
		return
	}
	panic("seqNum must have 1 or 2 bytes")
}

// panic if len(iv) is < 8
func FillIVSequence(iv []byte, seq uint64) {
	maskBytes := iv[len(iv)-8:]
	mask := binary.BigEndian.Uint64(maskBytes)
	binary.BigEndian.PutUint64(maskBytes, seq^mask)
}

func NewChacha20Poly1305(key []byte) cipher.AEAD {
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("chacha20poly1305.NewCipher fails " + err.Error())
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
