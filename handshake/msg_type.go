// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import "errors"

type MsgType byte

var ErrHandshakeFragmentTooShort = errors.New("handshake message fragment too short")
var ErrHandshakeFragmentEmpty = errors.New("handshake message fragment empty")
var ErrHandshakeFragmentInvalid = errors.New("handshake message fragment offset or length mismatch")

const (
	MsgTypeZero                = 0 // hello_request_RESERVED - we use it as "message not set" flag
	MsgTypeClientHello MsgType = 1
	MsgTypeServerHello MsgType = 2
	// HelloRetryRequest message uses the same structure as the ServerHello, but with Random set to the special value
	// SHA-256 of "HelloRetryRequest": CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
	// [rfc8446:4.1.3]
	MsgTypeNewSessionTicket    MsgType = 4
	MsgTypeEndOfEarlyData      MsgType = 5
	MsgTypeEncryptedExtensions MsgType = 8
	MsgTypeRequestConnectionID MsgType = 9
	MsgTypeNewConnectionID     MsgType = 10
	MsgTypeCertificate         MsgType = 11
	MsgTypeCertificateRequest  MsgType = 13
	MsgTypeCertificateVerify   MsgType = 15
	MsgTypeFinished            MsgType = 20
	MsgTypeKeyUpdate           MsgType = 24
	MsgTypeMessageHash         MsgType = 254 // synthetic message, never transmitted [rfc9147:5.1]
)

func MsgTypeToName(t MsgType) string {
	switch t {
	case MsgTypeZero:
		return "<zero>"
	case MsgTypeClientHello:
		return "ClientHello"
	case MsgTypeServerHello:
		return "ServerHello"
	case MsgTypeNewSessionTicket:
		return "NewSessionTicket"
	case MsgTypeEndOfEarlyData:
		return "EndOfEarlyData"
	case MsgTypeEncryptedExtensions:
		return "EncryptedExtensions"
	case MsgTypeRequestConnectionID:
		return "RequestConnectionId"
	case MsgTypeNewConnectionID:
		return "NewConnectionId"
	case MsgTypeCertificate:
		return "Certificate"
	case MsgTypeCertificateRequest:
		return "CertificateRequest"
	case MsgTypeCertificateVerify:
		return "CertificateVerify"
	case MsgTypeFinished:
		return "Finished"
	case MsgTypeKeyUpdate:
		return "KeyUpdate"
	case MsgTypeMessageHash:
		return "MessageHash"
	default:
		return "<unknown>"
	}
}
