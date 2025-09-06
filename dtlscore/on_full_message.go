// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"fmt"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
)

func (hctx *handshakeContext) receivedFullMessage(conn *Connection, msg handshake.Message) error {
	switch msg.MsgType {
	case handshake.MsgTypeServerHello:
		var msgParsed handshake.MsgServerHello
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.WarnPlaintextServerHelloParsing
		}
		return conn.state().OnServerHello(conn, msg, msgParsed)
	case handshake.MsgTypeEncryptedExtensions:
		var msgParsed handshake.ExtensionsSet
		if err := msgParsed.Parse(msg.Body, false, false, true, false, nil); err != nil {
			return dtlserrors.ErrExtensionsMessageParsing
		}
		fmt.Printf("encrypted extensions parsed: %+v\n", msgParsed)
		msg.AddToHash(hctx.transcriptHasher)
		return conn.state().OnEncryptedExtensions(conn, msg, msgParsed)
	case handshake.MsgTypeCertificate:
		var msgParsed handshake.MsgCertificate
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.ErrCertificateMessageParsing
		}
		// We do not want checks here, because receiving goroutine should not be blocked for long
		// We have to first receive everything up to finished, send acks,
		// then offload ECC to separate core and trigger state machine depending on result
		fmt.Printf("certificate parsed: %+v\n", msgParsed)
		msg.AddToHash(hctx.transcriptHasher)
		return conn.state().OnCertificate(conn, msg, msgParsed)
	case handshake.MsgTypeCertificateVerify:
		var msgParsed handshake.MsgCertificateVerify
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.ErrCertificateVerifyMessageParsing
		}
		return conn.state().OnCertificateVerify(conn, msg, msgParsed)
	case handshake.MsgTypeFinished:
		var msgParsed handshake.MsgFinished
		if err := msgParsed.Parse(msg.Body); err != nil {
			return dtlserrors.ErrFinishedMessageParsing
		}

		return conn.state().OnFinished(conn, msg, msgParsed)
	case handshake.MsgTypeClientHello:
	case handshake.MsgTypeKeyUpdate:
	case handshake.MsgTypeNewSessionTicket:
		panic("should be handled in smHandshake.OnHandshakeMsgFragment")
	default:
		// TODO - process all messages in standard, generate error for the rest
		fmt.Printf("TODO - encrypted message type %d not supported\n", msg.MsgType)
	}
	return nil
}
