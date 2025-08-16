package format

import (
	"encoding/binary"
	"errors"
)

const PlaintextRecordHeaderSize = 13
const MaxPlaintextRecordLength = 16384                           // [rfc8446:5.1]
const MaxCiphertextRecordLength = MaxPlaintextRecordLength + 256 // [rfc8446:5.2]

// This does not include CID size and AEAD seal, they are deterministic but depend on runtime parameters
// 5 is first byte plus 16-bit seqnum plus 16-bit length
// 1 is content type size
// 4 is max padding
const MaxOutgoingCiphertextRecordOverhead = 5 + 1 + 4

const (
	PlaintextContentTypeAlert           = 21
	PlaintextContentTypeHandshake       = 22
	PlaintextContentTypeApplicationData = 23
	// PlaintextContentTypeHeartbeat       = 24 // [rfc6520] should not be received without negotiating extension. We choose to error on it.
	PlaintextContentTypeAck = 26
)

type PlaintextRecordHeader struct {
	ContentType byte
	// Version is fixed, not stored
	// epoch is fixed to 0 for plaintext messages, do not store
	SequenceNumber uint64 // stored as 48-bit
	// Length is checked, not stored
}

var ErrPlaintextRecordHeaderTooShort = errors.New("plaintext record header too short")
var ErrPlaintextRecordBodyTooShort = errors.New("plaintext record body too short")
var ErrPlaintextRecordBodyTooLong = errors.New("plaintext record body exceeds 2^14")
var ErrPlaintextRecordBodyEpochNonZero = errors.New("plaintext record body non zero epoch")
var ErrPlaintextRecordWrongLegacyRecordVersion = errors.New("plaintext record wrong legacy record version")

func IsCiphertextRecord(fb byte) bool {
	return fb&0b11100000 == 0b00100000
}

func IsInnerPlaintextRecord(fb byte) bool {
	// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3, so we do not classify them as valid here
	return fb == PlaintextContentTypeAlert ||
		fb == PlaintextContentTypeHandshake ||
		fb == PlaintextContentTypeApplicationData ||
		// fb == PlaintextContentTypeHeartbeat || - uncomment if we implement support
		fb == PlaintextContentTypeAck
}

func IsPlaintextRecord(fb byte) bool {
	// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3, so we do not classify them as valid here
	// TODO - contact DTLS team
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
	epoch := binary.BigEndian.Uint16(datagram[3:5])
	if epoch != 0 {
		return 0, nil, ErrPlaintextRecordBodyEpochNonZero
	}
	hdr.SequenceNumber = binary.BigEndian.Uint64(datagram[3:11]) & 0xFFFFFFFFFFFF
	length := int(binary.BigEndian.Uint16(datagram[11:13]))
	if length > MaxPlaintextRecordLength { // TODO - generate record_overflow alert
		return 0, nil, ErrPlaintextRecordBodyTooLong
	}
	endOffset := PlaintextRecordHeaderSize + length
	if len(datagram) < endOffset {
		return 0, nil, ErrPlaintextRecordBodyTooShort
	}
	return endOffset, datagram[13:endOffset], nil
}

func (hdr *PlaintextRecordHeader) Write(datagram []byte, length int) []byte {
	datagram = append(datagram, hdr.ContentType, 0xFE, 0xFD)
	datagram = binary.BigEndian.AppendUint16(datagram, 0)
	datagram = AppendUint48(datagram, hdr.SequenceNumber)
	if length < 0 || length > MaxPlaintextRecordLength {
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
var ErrCiphertextRecordBodyTooLong = errors.New("cipher text record body exceeds 2^14 + 256")

var ErrRecordTypeFailedToParse = errors.New("record type failed to parse")

func NewCiphertextRecordHeader(hasCID bool, has16bitSeqNum bool, hasLength bool, epoch uint16) CiphertextRecordHeader {
	result := CiphertextRecordHeader{FirstByte: 0b00100000 | (byte(epoch) & 0b00000011)}
	if hasCID {
		result.FirstByte |= 0b00010000
	}
	if has16bitSeqNum {
		result.FirstByte |= 0b00001000
	}
	if hasLength {
		result.FirstByte |= 0b00000100
	}
	return result
}

func (hdr *CiphertextRecordHeader) HasCID() bool         { return hdr.FirstByte&0b00010000 != 0 }
func (hdr *CiphertextRecordHeader) Has16BitSeqNum() bool { return hdr.FirstByte&0b00001000 != 0 }
func (hdr *CiphertextRecordHeader) HasLength() bool      { return hdr.FirstByte&0b00000100 != 0 }
func (hdr *CiphertextRecordHeader) Epoch() byte          { return hdr.FirstByte & 0b00000011 }

func (hdr *CiphertextRecordHeader) MatchesEpoch(epoch uint16) bool {
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

func (hdr *CiphertextRecordHeader) ClosestSequenceNumber(seqNumData []byte, expectedSN uint64) (uint16, uint64) { // return garbage before decryption or after encryption
	if hdr.Has16BitSeqNum() {
		seq := binary.BigEndian.Uint16(seqNumData)
		return seq, closestSequenceNumber(seq, expectedSN, 0x10000)
	}
	seq := uint16(seqNumData[0])
	return seq, closestSequenceNumber(seq, expectedSN, 0x100)
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
	if length > MaxCiphertextRecordLength { // TODO - generate record_overflow alert
		return 0, nil, nil, nil, nil, ErrCiphertextRecordBodyTooLong
	}
	offset += 2
	endOffset := offset + length
	if len(datagram) < endOffset {
		return 0, nil, nil, nil, nil, ErrCiphertextRecordTooShortLength
	}
	return endOffset, cid, seqNum, datagram[:offset], datagram[offset:endOffset], nil
}
