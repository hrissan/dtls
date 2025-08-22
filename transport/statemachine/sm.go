// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/sha256"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

// TODO - move out
func (hctx *handshakeContext) generateFinished(conn *ConnectionImpl) handshake.Message {
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHashStorage [constants.MaxHashLength]byte
	finishedTranscriptHash := hctx.transcriptHasher.Sum(finishedTranscriptHashStorage[:0])

	mustBeFinished := keys.ComputeFinished(sha256.New(), hctx.handshakeTrafficSecretSend[:], finishedTranscriptHash)

	msg := handshake.MsgFinished{
		VerifyDataLength: len(mustBeFinished),
	}
	copy(msg.VerifyData[:], mustBeFinished)
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeFinished,
		Body:    messageBody,
	}
}

type stateMachineStateID byte

const (
	smIDClosed                                stateMachineStateID = 0
	smIDClientSentHello                       stateMachineStateID = 1
	smIDHandshakeServerExpectClientHello2     stateMachineStateID = 2
	smIDHandshakeServerExpectFinished         stateMachineStateID = 3
	smIDHandshakeClientExpectServerHRR        stateMachineStateID = 4
	smIDHandshakeClientExpectServerHello      stateMachineStateID = 5
	smIDHandshakeClientExpectServerEE         stateMachineStateID = 6
	smIDHandshakeClientExpectServerCert       stateMachineStateID = 7
	smIDHandshakeClientExpectServerCertVerify stateMachineStateID = 8
	smIDHandshakeClientExpectServerFinished   stateMachineStateID = 9
	smIDPostHandshake                         stateMachineStateID = 10
)

var stateMachineStates = [...]StateMachine{
	smIDClosed:                                &smClosed{},
	smIDClientSentHello:                       &smClientSentHello1{},
	smIDHandshakeServerExpectClientHello2:     &smHandshakeServerExpectClientHello2{},
	smIDHandshakeServerExpectFinished:         &smHandshakeServerExpectFinished{},
	smIDHandshakeClientExpectServerHRR:        &smHandshakeClientExpectServerHRR{},
	smIDHandshakeClientExpectServerHello:      &smHandshakeClientExpectServerHello{},
	smIDHandshakeClientExpectServerEE:         &smHandshakeClientExpectEE{},
	smIDHandshakeClientExpectServerCert:       &smHandshakeClientExpectCert{},
	smIDHandshakeClientExpectServerCertVerify: &smHandshakeClientExpectCertVerify{},
	smIDHandshakeClientExpectServerFinished:   &smHandshakeClientExpectFinished{},
	smIDPostHandshake:                         &smPostHandshake{},
}

type StateMachine interface {
	// this is not in state machine and always ignored
	// TODO - contact standard authors to clarify [rfc9147:4.1]
	// OnPlaintextAck(conn *ConnectionImpl)

	//OnPlaintextAlert(conn *ConnectionImpl)
	//OnPlaintextClientHello(conn *ConnectionImpl)
	//OnPlaintextServerHello(conn *ConnectionImpl)

	OnHandshakeMsgFragment(conn *ConnectionImpl, opts *options.TransportOptions,
		fragment handshake.Fragment, rn record.Number) error

	OnServerHello(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgServerHello) error
	OnEncryptedExtensions(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.ExtensionsSet) error
	OnCertificate(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgCertificate) error
	OnCertificateVerify(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgCertificateVerify) error
	OnFinished(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.MsgFinished) error

	//OnEncryptedApplicationData(conn *ConnectionImpl)
	//OnEncryptedAlert(conn *ConnectionImpl)
	//OnEncryptedKeyUpdate(conn *ConnectionImpl)
}

type smClientSentHello1 struct {
	smHandshake
}

// If we have no connection (conn == null)
// client:
//   * -> ignore, those are either attack or retransmissions from previous connection
// server:
//   plaintext ClientHello
//     w/o cookie or key_share
//       if params supported
//         send ServerHelloRetryRequest
//       if params not supported
//         send stateless error (correct alert code)
//     with cookie
//       old timestamp or invalid cookie
//         send stateless alert (replay or attack)
//       correct cookie timestamp
//         create connection, add to map, create handshake, [start handshake] send ServerHello after ECC goroutine finishes
//   plaintext ServerHello
//     send stateless alert (replay or attack)
//   plaintext * handshake message - ignore, do not pass to state machine
//   plaintext alert
//     ignore
//   encrypted record
//     send stateless error (correct alert code, but which one?) cannot decrypt

// If we have connection, but not yet established (hctx != null)
// both:
//   encrypted record - decrypt
//   encrypted application data -> [close connecton]
//   encrypted KeyUpdate -> [close] send alert unexpected message
//   encrypted NewSessionTicket -> [close] send alert unexpected message
// client [sent ClientHello1]":
//   plaintext ServerHelloRetryRequest
//     [-> sent ClientHello2]
//   plaintext ServerHello
//     [-> received ServerHello]
//   plaintext * handshake message - ignore, do not pass to state machine
//   encrypted record
//     ignore
// client [sent ClientHello2]
//   plaintext ServerHelloRetryRequest
//     resend ClientHello2
//   plaintext ServerHello
//     [-> received ServerHello]
//   plaintext * handshake message - ignore, do not pass to state machine
//   encrypted record
//     ignore

// If we have Connection established (hctx == null), both peers already destroyed their epoch < 3 keys
// both:
//   encrypted record - decrypt
//   encrypted KeyUpdate -> start key update
//   encrypted application data -> deliver
// server: (either attacker, or client who lost/closed association and wants a new connection)
//   plaintext ClientHello w/o cookie ->
//     send encrypted empty ack + send ServerHelloRetryRequest, remember cookie timestamp in connection
//   plaintext ClientHello w old cookie timestamp or invalid cookie ->
//     replay or attack, do nothing
//   plaintext ClientHello w correct cookie timestamp ->
//     destroy connection without sending alert + start handshake
//     we could have completely separate handshake state machine, so would auth client
//     before destroying old connection, but that requires 2 complete sets of keys/secrets
//     and complicated logic, so do it later or never.
//   plaintext ServerHello -> ignore, send warning
//   * -> close
// client:
//   encrypted NewSessionTicket -> deliver
//   * -> close
