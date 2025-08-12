package format

import (
	"encoding/binary"
	"errors"
	"math"
)

const PlaintextRecordHeaderSize = 13

type PlaintextRecordHeader struct {
	ContentType byte
	// Version is fixed, not stored
	Epoch          uint16
	SequenceNumber uint64 // stored as 48-bit
	// Length is checked, not stored
}

var ErrPlaintextRecordHeaderTooShort = errors.New("plaintext record header too short")
var ErrPlaintextRecordBodyTooShort = errors.New("plaintext record body too short")
var ErrPlaintextRecordWrongLegacyRecordVersion = errors.New("plaintext record wrong legacy record version")

func IsCiphertextRecord(fb byte) bool {
	return fb&0b11100000 == 0b00100000
}

const PlaintextContentTypeAlert = 21
const PlaintextContentTypeHandshake = 22
const PlaintextContentTypeAck = 26

func IsPlaintextRecord(fb byte) bool {
	// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3, so we do not classify them as valid here
	return fb == PlaintextContentTypeAlert || fb == PlaintextContentTypeHandshake // || fb == PlaintextContentTypeAck
}

func (hdr *PlaintextRecordHeader) Parse(datagram []byte) (n int, body []byte, err error) {
	if len(datagram) < PlaintextRecordHeaderSize {
		return 0, nil, ErrPlaintextRecordHeaderTooShort
	}
	hdr.ContentType = datagram[0] // checked elsewhere
	if datagram[1] != 0xFE || datagram[2] != 0xFD {
		return 0, nil, ErrPlaintextRecordWrongLegacyRecordVersion
	}
	hdr.Epoch = binary.BigEndian.Uint16(datagram[3:5])
	hdr.SequenceNumber = binary.BigEndian.Uint64(datagram[3:11]) & 0xFFFFFFFFFFFF
	endOffset := PlaintextRecordHeaderSize + int(binary.BigEndian.Uint16(datagram[11:13]))
	if len(datagram) < endOffset {
		return 0, nil, ErrPlaintextRecordBodyTooShort
	}
	return endOffset, datagram[13:endOffset], nil
}

func (hdr *PlaintextRecordHeader) Write(datagram []byte, length int) []byte {
	datagram = append(datagram, hdr.ContentType, 0xFE, 0xFD)
	datagram = binary.BigEndian.AppendUint16(datagram, hdr.Epoch)
	datagram = AppendUint48(datagram, hdr.SequenceNumber)
	if length < 0 || length > math.MaxUint16 {
		panic("length of plaintext record out of range")
	}
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(length))
	return datagram
}

type CiphertextRecordHeader struct {
	FirstByte byte
	// CID is variable length, not stored
	// SequenceNumberBytes [2]byte // not stored because encrypted/decrypted in place
	// Length is checked, not stored
}

var ErrCiphertextRecordTooShort = errors.New("cipher text record header too short")
var ErrCiphertextRecordTooShortLength = errors.New("cipher text record body too short (explicit length)")

var ErrRecordTypeFailedToParse = errors.New("record type failed to parse")

func (hdr *CiphertextRecordHeader) HasCID() bool         { return hdr.FirstByte&0b00010000 != 0 }
func (hdr *CiphertextRecordHeader) Has16BitSeqNum() bool { return hdr.FirstByte&0b00001000 != 0 }
func (hdr *CiphertextRecordHeader) HasLength() bool      { return hdr.FirstByte&0b00000100 != 0 }
func (hdr *CiphertextRecordHeader) Epoch() byte          { return hdr.FirstByte & 0b00000011 }

func closestSequenceNumber(seq uint16, expectedSN uint64, mask uint64) uint64 {
	expectedSN1 := (expectedSN &^ mask) | uint64(seq)
	expectedSN2 := ((expectedSN &^ mask) | uint64(seq)) + mask + 1
	if expectedSN1 > expectedSN {
		panic("expected SN algorithm failure") // TODO - remove after debugging
	}
	if expectedSN2 < expectedSN {
		panic("expected SN algorithm failure") // TODO - remove after debugging
	}
	if expectedSN-expectedSN1 < expectedSN2-expectedSN { // return whatever is closest
		return expectedSN1
	}
	return expectedSN2
}

func (hdr *CiphertextRecordHeader) ClosestSequenceNumber(seqNumData []byte, expectedSN uint64) uint64 { // return garbage before decryption or after encryption
	if hdr.Has16BitSeqNum() {
		seq := binary.BigEndian.Uint16(seqNumData)
		return closestSequenceNumber(seq, expectedSN, 0xFFFF)
	}
	seq := seqNumData[0]
	return closestSequenceNumber(uint16(seq), expectedSN, 0xFF)
}

func (hdr *CiphertextRecordHeader) Parse(datagram []byte, cIDLength int) (n int, cid []byte, seqNum []byte, header []byte, body []byte, err error) {
	hdr.FirstByte = datagram[0] // !empty checked elsewhere
	offset := 1
	if hdr.HasCID() {
		if len(datagram) < 1+cIDLength {
			return 0, nil, nil, nil, nil, ErrCiphertextRecordTooShort
		}
		cid = datagram[1 : 1+cIDLength]
		offset = 1 + cIDLength
	}
	if hdr.Has16BitSeqNum() {
		if len(datagram) < offset+2 {
			return 0, nil, nil, nil, nil, ErrCiphertextRecordTooShort
		}
		seqNum = datagram[offset : offset+2]
		offset += 2
	} else {
		if len(datagram) < offset+1 {
			return 0, nil, nil, nil, nil, ErrCiphertextRecordTooShort
		}
		seqNum = datagram[offset : offset+1]
		offset += 1
	}
	if !hdr.HasLength() {
		return len(datagram), cid, seqNum, datagram[:offset], datagram[offset:], nil
	}
	if len(datagram) < offset+2 {
		return 0, nil, nil, nil, nil, ErrCiphertextRecordTooShort
	}
	length := int(binary.BigEndian.Uint16(datagram[offset:]))
	offset += 2
	endOffset := offset + length
	if len(datagram) < endOffset {
		return 0, nil, nil, nil, nil, ErrCiphertextRecordTooShortLength
	}
	return endOffset, cid, seqNum, datagram[:offset], datagram[offset:endOffset], nil
}
