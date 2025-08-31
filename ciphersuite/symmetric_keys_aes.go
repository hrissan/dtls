// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/safecast"
)

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

func (keys *SymmetricKeysAES) EncryptSequenceNumbersMask(cipherText []byte) ([2]byte, error) {
	var mask [16]byte
	if len(cipherText) < keys.SN.BlockSize() {
		return [2]byte{}, dtlserrors.WarnCipherTextTooShortForSNDecryption
	}
	keys.SN.Encrypt(mask[:], cipherText)
	return [2]byte(mask[0:2]), nil
}

func (keys *SymmetricKeysAES) PrepareProtect(datagramLeft []byte, use8BitSeq bool) (hdrSize int, insideBody []byte, ok bool) {
	hdrSize = record.OutgoingCiphertextRecordHeader16
	if use8BitSeq {
		hdrSize = record.OutgoingCiphertextRecordHeader8
	}
	overhead := hdrSize + 1 + record.MaxOutgoingCiphertextRecordPadding + constants.AEADSealSize
	userSpace := len(datagramLeft) - overhead
	if userSpace < 0 {
		return 0, nil, false
	}
	return hdrSize, datagramLeft[hdrSize : hdrSize+userSpace], true
}

func (keys *SymmetricKeysAES) Protect(rn record.Number, encryptSN bool, recordType byte, datagramLeft []byte, hdrSize int, insideSize int) (recordSize int) {
	fmt.Printf("constructing ciphertext type %d with rn={%d,%d} hdrSize = %d body: %x\n", recordType, rn.Epoch(), rn.SeqNum(), hdrSize, datagramLeft[hdrSize:hdrSize+insideSize])

	iv := keys.WriteIV
	FillIVSequence(iv[:], rn.SeqNum())

	// format of our encrypted record is fixed.
	// Saving 1 byte for the sequence number seems very niche.
	// Saving on not including length of the last datagram is also very hard.
	// At the point we know it is the last one, we cannot not change header,
	// because it is "additional data" for AEAD
	firstByte := record.CiphertextHeaderFirstByte(false, hdrSize == record.OutgoingCiphertextRecordHeader16, true, rn.Epoch())
	// panic below would mean, caller violated invariant of using datagram space
	datagramLeft[0] = firstByte
	datagramLeft[hdrSize+insideSize] = recordType
	insideSize++

	padding := (insideSize + 1) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding; i++ {
		datagramLeft[hdrSize+insideSize] = 0
		insideSize++
	}

	var seqNumData []byte
	if hdrSize == record.OutgoingCiphertextRecordHeader8 {
		seqNumData = datagramLeft[1:2]
		seqNumData[0] = byte(rn.SeqNum()) // truncation
		binary.BigEndian.PutUint16(datagramLeft[2:], safecast.Cast[uint16](insideSize+constants.AEADSealSize))
	} else {
		seqNumData = datagramLeft[1:3]
		binary.BigEndian.PutUint16(seqNumData, uint16(rn.SeqNum())) // truncation
		binary.BigEndian.PutUint16(datagramLeft[3:], safecast.Cast[uint16](insideSize+constants.AEADSealSize))
	}

	encrypted := keys.Write.Seal(datagramLeft[hdrSize:hdrSize], iv[:], datagramLeft[hdrSize:hdrSize+insideSize], datagramLeft[:hdrSize])
	if &encrypted[0] != &datagramLeft[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagramLeft[hdrSize:hdrSize+insideSize+constants.AEADSealSize]) {
		panic("gcm.Seal length mismatch")
	}

	if encryptSN {
		mask, err := keys.EncryptSequenceNumbersMask(datagramLeft[hdrSize:])
		if err != nil {
			panic("cipher text too short when sending")
		}
		encryptSequenceNumbers(seqNumData, mask)
	}
	//	fmt.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return hdrSize + insideSize + constants.AEADSealSize
}

func (keys *SymmetricKeysAES) Deprotect(hdr record.Ciphertext, encryptSN bool, expectedSN uint64) (decrypted []byte, seq uint64, contentType byte, err error) {
	if encryptSN {
		mask, err := keys.EncryptSequenceNumbersMask(hdr.Body)
		if err != nil {
			return nil, 0, 0, err
		}
		encryptSequenceNumbers(hdr.SeqNum, mask)
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
