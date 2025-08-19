package handshake

import (
	"encoding/binary"
	"errors"
	"hash"

	"github.com/hrissan/tinydtls/format"
)

type MsgType byte

var ErrHandshakeMsgTooShort = errors.New("handshake message too short")

const (
	HandshakeTypeZero                = 0 // hello_request_RESERVED - we use it as "message not set" flag
	HandshakeTypeClientHello MsgType = 1
	HandshakeTypeServerHello MsgType = 2
	// HelloRetryRequest message uses the same structure as the ServerHello, but with Random set to the special value
	// SHA-256 of "HelloRetryRequest": CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
	// [rfc8446:4.1.3]
	HandshakeTypeNewSessionTicket    MsgType = 4
	HandshakeTypeEndOfEarlyData      MsgType = 5
	HandshakeTypeEncryptedExtensions MsgType = 8
	HandshakeTypeRequestConnectionID MsgType = 9
	HandshakeTypeNewConnectionID     MsgType = 10
	HandshakeTypeCertificate         MsgType = 11
	HandshakeTypeCertificateRequest  MsgType = 13
	HandshakeTypeCertificateVerify   MsgType = 15
	HandshakeTypeFinished            MsgType = 20
	HandshakeTypeKeyUpdate           MsgType = 24
	HandshakeTypeMessageHash         MsgType = 254 // synthetic message, never transmitted [rfc9147:5.1]
)

const MessageHandshakeHeaderSize = 12

func HandshakeTypeToName(t MsgType) string {
	switch t {
	case HandshakeTypeClientHello:
		return "ClientHello"
	case HandshakeTypeServerHello:
		return "ServerHello"
	case HandshakeTypeNewSessionTicket:
		return "NewSessionTicket"
	case HandshakeTypeEndOfEarlyData:
		return "EndOfEarlyData"
	case HandshakeTypeEncryptedExtensions:
		return "EncryptedExtensions"
	case HandshakeTypeRequestConnectionID:
		return "RequestConnectionId"
	case HandshakeTypeNewConnectionID:
		return "NewConnectionId"
	case HandshakeTypeCertificate:
		return "Certificate"
	case HandshakeTypeCertificateRequest:
		return "CertificateRequest"
	case HandshakeTypeCertificateVerify:
		return "CertificateVerify"
	case HandshakeTypeFinished:
		return "Finished"
	case HandshakeTypeKeyUpdate:
		return "KeyUpdate"
	case HandshakeTypeMessageHash:
		return "MessageHash"
	default:
		return "<unknown>"
	}
}

type FragmentInfo struct {
	MsgSeq         uint16
	FragmentOffset uint32 // stored as 24-bit
	FragmentLength uint32 // stored as 24-bit
}

type MsgFragmentHeader struct {
	HandshakeType MsgType
	Length        uint32 // stored as 24-bit
	FragmentInfo
}

func (hdr *MsgFragmentHeader) IsFragmented() bool {
	return hdr.FragmentOffset != 0 || hdr.FragmentLength != hdr.Length
}

// only first 2 fields are part of transcript hash
func (hdr *MsgFragmentHeader) AddToHash(transcriptHasher hash.Hash) {
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], (uint32(hdr.HandshakeType)<<24)+hdr.Length)
	_, _ = transcriptHasher.Write(result[:])
	return
}

func (hdr *MsgFragmentHeader) Parse(record []byte) error {
	if len(record) < MessageHandshakeHeaderSize {
		return ErrHandshakeMsgTooShort
	}
	hdr.HandshakeType = MsgType(record[0])
	hdr.Length = binary.BigEndian.Uint32(record[0:4]) & 0xFFFFFF
	hdr.MsgSeq = binary.BigEndian.Uint16(record[4:6])
	hdr.FragmentOffset = binary.BigEndian.Uint32(record[5:9]) & 0xFFFFFF
	hdr.FragmentLength = binary.BigEndian.Uint32(record[8:12]) & 0xFFFFFF
	return nil
}

func (hdr *MsgFragmentHeader) ParseWithBody(record []byte) (n int, body []byte, err error) {
	if err := hdr.Parse(record); err != nil {
		return 0, nil, err
	}
	endOffset := MessageHandshakeHeaderSize + int(hdr.FragmentLength)
	if len(record) < endOffset {
		return 0, nil, ErrHandshakeMsgTooShort
	}
	return endOffset, record[MessageHandshakeHeaderSize:endOffset], nil
}

func (hdr *MsgFragmentHeader) Write(datagram []byte) []byte {
	datagram = append(datagram, byte(hdr.HandshakeType))
	datagram = format.AppendUint24(datagram, hdr.Length)
	datagram = binary.BigEndian.AppendUint16(datagram, hdr.MsgSeq)
	datagram = format.AppendUint24(datagram, hdr.FragmentOffset)
	datagram = format.AppendUint24(datagram, hdr.FragmentLength)
	return datagram
}
