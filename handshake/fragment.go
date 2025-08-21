// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"encoding/binary"

	"github.com/hrissan/dtls/format"
)

const FragmentHeaderSize = 12

type FragmentInfo struct {
	MsgSeq         uint16
	FragmentOffset uint32 // stored as 24-bit
	FragmentLength uint32 // stored as 24-bit
}

type FragmentHeader struct {
	MsgType MsgType
	Length  uint32 // stored as 24-bit
	FragmentInfo
}

type Fragment struct {
	Header FragmentHeader
	Body   []byte // TODO - reuse in rope
}

func (hdr *FragmentHeader) IsFragmented() bool {
	return hdr.FragmentOffset != 0 || hdr.FragmentLength != hdr.Length
}

func (hdr *FragmentHeader) Parse(record []byte) error {
	if len(record) < FragmentHeaderSize {
		return ErrHandshakeFragmentTooShort
	}
	hdr.MsgType = MsgType(record[0])
	hdr.Length = binary.BigEndian.Uint32(record[0:4]) & 0xFFFFFF
	hdr.MsgSeq = binary.BigEndian.Uint16(record[4:6])
	hdr.FragmentOffset = binary.BigEndian.Uint32(record[5:9]) & 0xFFFFFF
	hdr.FragmentLength = binary.BigEndian.Uint32(record[8:12]) & 0xFFFFFF
	if hdr.FragmentLength == 0 {
		return ErrHandshakeFragmentEmpty
	}
	if hdr.FragmentOffset >= hdr.Length || hdr.FragmentOffset+hdr.FragmentLength > hdr.Length {
		return ErrHandshakeFragmentInvalid
	}
	return nil
}

func (hdr *FragmentHeader) Write(datagram []byte) []byte {
	if hdr.FragmentLength == 0 {
		panic("attempt to write empty handshake message fragment with offset or length mismatch")
	}
	if hdr.FragmentOffset >= hdr.Length || hdr.FragmentOffset+hdr.FragmentLength > hdr.Length {
		panic("attempt to write handshake message fragment with offset or length mismatch")
	}
	datagram = append(datagram, byte(hdr.MsgType))
	datagram = format.AppendUint24(datagram, hdr.Length)
	datagram = binary.BigEndian.AppendUint16(datagram, hdr.MsgSeq)
	datagram = format.AppendUint24(datagram, hdr.FragmentOffset)
	datagram = format.AppendUint24(datagram, hdr.FragmentLength)
	return datagram
}

func (fragment *Fragment) Parse(record []byte) (n int, err error) {
	if err := fragment.Header.Parse(record); err != nil {
		return 0, err
	}
	endOffset := FragmentHeaderSize + int(fragment.Header.FragmentLength)
	if len(record) < endOffset {
		return 0, ErrHandshakeFragmentTooShort
	}
	fragment.Body = record[FragmentHeaderSize:endOffset]
	return endOffset, nil
}
