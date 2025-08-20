// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package record

import (
	"encoding/binary"
	"errors"
)

const MaxCiphertextRecordLength = MaxPlaintextRecordLength + 256 // [rfc8446:5.2]

// This does not include CID size and AEAD seal, they are deterministic but depend on runtime parameters
// 5 is first byte plus 16-bit seqnum plus 16-bit length
// 1 is content type size
// 4 is max padding
const OutgoingCiphertextRecordHeader = 5
const MaxOutgoingCiphertextRecordOverhead = OutgoingCiphertextRecordHeader + 1 + 4

func IsCiphertextRecord(fb byte) bool {
	return fb&0b11100000 == 0b00100000
}

type Ciphertext struct {
	FirstByte byte
	CID       []byte // alias to original slice
	SeqNum    []byte // alias to original slice to be encrypted/decrypted in place
	Header    []byte // alias to original slice for AEAD
	// Length is checked, not stored
	Body []byte // alias to original slice
}

var ErrCiphertextRecordTooShort = errors.New("cipher text record header too short")
var ErrCiphertextRecordTooShortLength = errors.New("cipher text record body too short (explicit length)")
var ErrCiphertextRecordBodyTooLong = errors.New("cipher text record body exceeds 2^14 + 256")

var ErrRecordTypeFailedToParse = errors.New("record type failed to parse")

func CiphertextHeaderFirstByte(hasCID bool, has16bitSeqNum bool, hasLength bool, epoch uint16) byte {
	result := 0b00100000 | (byte(epoch) & 0b00000011)
	if hasCID {
		result |= 0b00010000
	}
	if has16bitSeqNum {
		result |= 0b00001000
	}
	if hasLength {
		result |= 0b00000100
	}
	return result
}

func (hdr *Ciphertext) HasCID() bool         { return hdr.FirstByte&0b00010000 != 0 }
func (hdr *Ciphertext) Has16BitSeqNum() bool { return hdr.FirstByte&0b00001000 != 0 }
func (hdr *Ciphertext) HasLength() bool      { return hdr.FirstByte&0b00000100 != 0 }
func (hdr *Ciphertext) Epoch() byte          { return hdr.FirstByte & 0b00000011 }

func (hdr *Ciphertext) MatchesEpoch(epoch uint16) bool {
	return byte(epoch&0b00000011) == hdr.Epoch()
}

func closestSequenceNumber(seq uint16, expectedSN uint64, mask uint64) uint64 {
	if expectedSN < mask/2 { // irregularity around 0
		return (expectedSN &^ (mask - 1)) | uint64(seq)
	}
	bottom := (expectedSN - mask/2)
	seqCandidate := (bottom &^ (mask - 1)) | uint64(seq)
	if seqCandidate < bottom {
		seqCandidate += mask
	}
	return seqCandidate
}

func (hdr *Ciphertext) ClosestSequenceNumber(seqNumData []byte, expectedSN uint64) (uint16, uint64) { // return garbage before decryption or after encryption
	if hdr.Has16BitSeqNum() {
		seq := binary.BigEndian.Uint16(seqNumData)
		return seq, closestSequenceNumber(seq, expectedSN, 0x10000)
	}
	seq := uint16(seqNumData[0])
	return seq, closestSequenceNumber(seq, expectedSN, 0x100)
}

func (hdr *Ciphertext) Parse(datagram []byte, cIDLength int) (n int, err error) {
	hdr.FirstByte = datagram[0] // !empty checked elsewhere
	offset := 1
	if hdr.HasCID() {
		if len(datagram) < 1+cIDLength {
			return 0, ErrCiphertextRecordTooShort
		}
		hdr.CID = datagram[1 : 1+cIDLength]
		offset = 1 + cIDLength
	}
	if hdr.Has16BitSeqNum() {
		if len(datagram) < offset+2 {
			return 0, ErrCiphertextRecordTooShort
		}
		hdr.SeqNum = datagram[offset : offset+2]
		offset += 2
	} else {
		if len(datagram) < offset+1 {
			return 0, ErrCiphertextRecordTooShort
		}
		hdr.SeqNum = datagram[offset : offset+1]
		offset += 1
	}
	if !hdr.HasLength() {
		hdr.Header = datagram[:offset]
		hdr.Body = datagram[offset:]
		return len(datagram), nil
	}
	if len(datagram) < offset+2 {
		return 0, ErrCiphertextRecordTooShort
	}
	length := int(binary.BigEndian.Uint16(datagram[offset:]))
	if length > MaxCiphertextRecordLength { // TODO - generate record_overflow alert
		return 0, ErrCiphertextRecordBodyTooLong
	}
	offset += 2
	endOffset := offset + length
	if len(datagram) < endOffset {
		return 0, ErrCiphertextRecordTooShortLength
	}
	hdr.Header = datagram[:offset]
	hdr.Body = datagram[offset:endOffset]
	return endOffset, nil
}
