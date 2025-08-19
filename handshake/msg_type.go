package handshake

import "errors"

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

func HandshakeTypeToName(t MsgType) string {
	switch t {
	case HandshakeTypeZero:
		return "<zero>"
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
