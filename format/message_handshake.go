package format

import (
	"encoding/binary"
	"errors"
	"hash"
)

var ErrHandshakeMsgTooShort = errors.New("handshake message too short")

const (
	// hello_request_RESERVED = 0 - we use it as "message not set" flag
	HandshakeTypeClientHello = 1
	HandshakeTypeServerHello = 2
	// HelloRetryRequest message uses the same structure as the ServerHello, but with Random set to the special value
	// SHA-256 of "HelloRetryRequest": CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
	// [rfc8446:4.1.3]
	HandshakeTypeNewSessionTicket    = 4
	HandshakeTypeEndOfEarlyData      = 5
	HandshakeTypeEncryptedExtensions = 8
	HandshakeTypeRequestConnectionID = 9
	HandshakeTypeNewConnectionID     = 10
	HandshakeTypeCertificate         = 11
	HandshakeTypeCertificateRequest  = 13
	HandshakeTypeCertificateVerify   = 15
	HandshakeTypeFinished            = 20
	HandshakeTypeKeyUpdate           = 24
	HandshakeTypeMessageHash         = 254 // synthetic message, never transmitted [rfc9147:5.1]
)

const MessageHandshakeHeaderSize = 12

func HandshakeTypeToName(t byte) string {
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

type HandshakeMsgFragmentHeader struct {
	HandshakeType byte
	Length        uint32 // stored as 24-bit
	FragmentInfo
}

func (hdr *HandshakeMsgFragmentHeader) IsFragmented() bool {
	return hdr.FragmentOffset != 0 || hdr.FragmentLength != hdr.Length
}

// only first 2 fields are part of transcript hash
func (hdr *HandshakeMsgFragmentHeader) AddToHash(transcriptHasher hash.Hash) {
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], (uint32(hdr.HandshakeType)<<24)+hdr.Length)
	_, _ = transcriptHasher.Write(result[:])
	return
}

func (hdr *HandshakeMsgFragmentHeader) Parse(record []byte) error {
	if len(record) < MessageHandshakeHeaderSize {
		return ErrHandshakeMsgTooShort
	}
	hdr.HandshakeType = record[0]
	hdr.Length = binary.BigEndian.Uint32(record[0:4]) & 0xFFFFFF
	hdr.MsgSeq = binary.BigEndian.Uint16(record[4:6])
	hdr.FragmentOffset = binary.BigEndian.Uint32(record[5:9]) & 0xFFFFFF
	hdr.FragmentLength = binary.BigEndian.Uint32(record[8:12]) & 0xFFFFFF
	return nil
}

func (hdr *HandshakeMsgFragmentHeader) ParseWithBody(record []byte) (n int, body []byte, err error) {
	if err := hdr.Parse(record); err != nil {
		return 0, nil, err
	}
	endOffset := MessageHandshakeHeaderSize + int(hdr.FragmentLength)
	if len(record) < endOffset {
		return 0, nil, ErrHandshakeMsgTooShort
	}
	return endOffset, record[MessageHandshakeHeaderSize:endOffset], nil
}

func (hdr *HandshakeMsgFragmentHeader) Write(datagram []byte) []byte {
	datagram = append(datagram, hdr.HandshakeType)
	datagram = AppendUint24(datagram, hdr.Length)
	datagram = binary.BigEndian.AppendUint16(datagram, hdr.MsgSeq)
	datagram = AppendUint24(datagram, hdr.FragmentOffset)
	datagram = AppendUint24(datagram, hdr.FragmentLength)
	return datagram
}
