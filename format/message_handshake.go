package format

import (
	"encoding/binary"
	"errors"
)

var ErrMessageHandshakeTooShort = errors.New("message handshake too short")

const (
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

func HandshakeTypeToName(t byte) string {
	switch t {
	case HandshakeTypeClientHello:
		return "client_hello"
	case HandshakeTypeServerHello:
		return "server_hello"
	case HandshakeTypeNewSessionTicket:
		return "new_session_ticket"
	case HandshakeTypeEndOfEarlyData:
		return "end_of_early_data"
	case HandshakeTypeEncryptedExtensions:
		return "encrypted_extensions"
	case HandshakeTypeRequestConnectionID:
		return "request_connection_id"
	case HandshakeTypeNewConnectionID:
		return "new_connection_id"
	case HandshakeTypeCertificate:
		return "certificate"
	case HandshakeTypeCertificateRequest:
		return "certificate_request"
	case HandshakeTypeCertificateVerify:
		return "certificate_verify"
	case HandshakeTypeFinished:
		return "finished"
	case HandshakeTypeKeyUpdate:
		return "key_update"
	case HandshakeTypeMessageHash:
		return "message_hash"
	default:
		return "unknown"
	}
}

type MessageHandshakeHeader struct {
	HandshakeType  byte
	Length         uint32 // stored as 24-bit
	MessageSeq     uint16
	FragmentOffset uint32 // stored as 24-bit
	FragmentLength uint32 // stored as 24-bit
}

func (hdr *MessageHandshakeHeader) IsFragmented() bool {
	return hdr.FragmentOffset != 0 || hdr.FragmentLength != hdr.Length
}

func (hdr *MessageHandshakeHeader) Parse(record []byte) (n int, body []byte, err error) {
	if len(record) < 12 {
		return 0, nil, ErrMessageHandshakeTooShort
	}
	hdr.HandshakeType = record[0]
	hdr.Length = binary.BigEndian.Uint32(record[0:4]) & 0xFFFFFF
	hdr.MessageSeq = binary.BigEndian.Uint16(record[4:6])
	hdr.FragmentOffset = binary.BigEndian.Uint32(record[5:9]) & 0xFFFFFF
	hdr.FragmentLength = binary.BigEndian.Uint32(record[8:12]) & 0xFFFFFF
	endOffset := 12 + int(hdr.FragmentLength)
	if len(record) < endOffset {
		return 0, nil, ErrMessageHandshakeTooShort
	}
	return endOffset, record[12:endOffset], nil
}

func (hdr *MessageHandshakeHeader) Write(datagram []byte) []byte {
	datagram = append(datagram, hdr.HandshakeType)
	datagram = AppendUint24(datagram, hdr.Length)
	datagram = binary.BigEndian.AppendUint16(datagram, hdr.MessageSeq)
	datagram = AppendUint24(datagram, hdr.FragmentOffset)
	datagram = AppendUint24(datagram, hdr.FragmentLength)
	return datagram
}
