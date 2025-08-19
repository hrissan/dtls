package record

import (
	"encoding/binary"
	"errors"

	"github.com/hrissan/tinydtls/format"
)

const PlaintextRecordHeaderSize = 13
const MaxPlaintextRecordLength = 16384 // [rfc8446:5.1]

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
	if length == 0 {
		return 0, nil, ErrPlaintextRecordBodyTooShort
	}
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
	datagram = format.AppendUint48(datagram, hdr.SequenceNumber)
	if length < 0 || length > MaxPlaintextRecordLength {
		panic("length of plaintext record out of range")
	}
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(length))
	return datagram
}
