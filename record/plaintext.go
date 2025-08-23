// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package record

import (
	"encoding/binary"
	"errors"

	"github.com/hrissan/dtls/format"
)

const PlaintextRecordHeaderSize = 13
const MaxPlaintextRecordLength = 16384 // [rfc8446:5.1]

const (
	RecordTypeAlert           = 21
	RecordTypeHandshake       = 22
	RecordTypeApplicationData = 23
	// PlaintextContentTypeHeartbeat       = 24 // [rfc6520] should not be received without negotiating extension. We choose to error on it.
	RecordTypeAck = 26
)

type PlaintextHeader struct {
	ContentType byte
	// Version is fixed, not stored
	// epoch is fixed to 0 for plaintext messages, do not store
	SequenceNumber uint64 // stored as 48-bit
	// Length is checked, not stored
}

type Plaintext struct {
	ContentType byte
	// Version is fixed, not stored
	// epoch is fixed to 0 for plaintext messages, do not store
	SequenceNumber uint64 // stored as 48-bit
	// Length is checked, not stored
	// Body is alias to buffer which must be parsed/saved and never retained
	Body []byte
}

var ErrPlaintextRecordHeaderTooShort = errors.New("plaintext record header too short")
var ErrPlaintextRecordBodyTooShort = errors.New("plaintext record body too short")
var ErrPlaintextRecordBodyTooLong = errors.New("plaintext record body exceeds 2^14")
var ErrPlaintextRecordBodyEpochNonZero = errors.New("plaintext record body non zero epoch")
var ErrPlaintextRecordWrongLegacyRecordVersion = errors.New("plaintext record wrong legacy record version")

func (hdr *Plaintext) Parse(datagram []byte) (n int, err error) {
	if len(datagram) < PlaintextRecordHeaderSize {
		return 0, ErrPlaintextRecordHeaderTooShort
	}
	hdr.ContentType = datagram[0] // checked elsewhere
	if datagram[1] != 0xFE || datagram[2] != 0xFD {
		return 0, ErrPlaintextRecordWrongLegacyRecordVersion
	}
	epoch := binary.BigEndian.Uint16(datagram[3:5])
	if epoch != 0 {
		return 0, ErrPlaintextRecordBodyEpochNonZero
	}
	hdr.SequenceNumber = binary.BigEndian.Uint64(datagram[3:11]) & 0xFFFFFFFFFFFF
	length := int(binary.BigEndian.Uint16(datagram[11:13]))
	if length == 0 {
		return 0, ErrPlaintextRecordBodyTooShort
	}
	if length > MaxPlaintextRecordLength { // TODO - generate record_overflow alert
		return 0, ErrPlaintextRecordBodyTooLong
	}
	endOffset := PlaintextRecordHeaderSize + length
	if len(datagram) < endOffset {
		return 0, ErrPlaintextRecordBodyTooShort
	}
	hdr.Body = datagram[13:endOffset]
	return endOffset, nil
}

func (hdr *PlaintextHeader) Write(datagram []byte, length uint16) []byte {
	datagram = append(datagram, hdr.ContentType, 0xFE, 0xFD)
	datagram = binary.BigEndian.AppendUint16(datagram, 0)
	datagram = format.AppendUint48(datagram, hdr.SequenceNumber)
	datagram = binary.BigEndian.AppendUint16(datagram, length)
	return datagram
}
