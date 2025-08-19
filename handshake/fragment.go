package handshake

import (
	"encoding/binary"
	"hash"

	"github.com/hrissan/tinydtls/format"
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

func (hdr *FragmentHeader) IsFragmented() bool {
	return hdr.FragmentOffset != 0 || hdr.FragmentLength != hdr.Length
}

// only first 2 fields are part of transcript hash
func (hdr *FragmentHeader) AddToHash(transcriptHasher hash.Hash) {
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], (uint32(hdr.MsgType)<<24)+hdr.Length)
	_, _ = transcriptHasher.Write(result[:])
	return
}

func (hdr *FragmentHeader) Parse(record []byte) error {
	if len(record) < FragmentHeaderSize {
		return ErrHandshakeMsgTooShort
	}
	hdr.MsgType = MsgType(record[0])
	hdr.Length = binary.BigEndian.Uint32(record[0:4]) & 0xFFFFFF
	hdr.MsgSeq = binary.BigEndian.Uint16(record[4:6])
	hdr.FragmentOffset = binary.BigEndian.Uint32(record[5:9]) & 0xFFFFFF
	hdr.FragmentLength = binary.BigEndian.Uint32(record[8:12]) & 0xFFFFFF
	return nil
}

func (hdr *FragmentHeader) ParseWithBody(record []byte) (n int, body []byte, err error) {
	if err := hdr.Parse(record); err != nil {
		return 0, nil, err
	}
	endOffset := FragmentHeaderSize + int(hdr.FragmentLength)
	if len(record) < endOffset {
		return 0, nil, ErrHandshakeMsgTooShort
	}
	return endOffset, record[FragmentHeaderSize:endOffset], nil
}

func (hdr *FragmentHeader) Write(datagram []byte) []byte {
	datagram = append(datagram, byte(hdr.MsgType))
	datagram = format.AppendUint24(datagram, hdr.Length)
	datagram = binary.BigEndian.AppendUint16(datagram, hdr.MsgSeq)
	datagram = format.AppendUint24(datagram, hdr.FragmentOffset)
	datagram = format.AppendUint24(datagram, hdr.FragmentLength)
	return datagram
}
