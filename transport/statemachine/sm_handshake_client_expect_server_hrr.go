// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectServerHRR struct {
	smHandshake
}

func (*smHandshakeClientExpectServerHRR) OnServerHello(conn *Connection, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	if err := conn.tr.IsSupportedServerHello(&msgParsed); err != nil {
		return err
	}
	if hctx.transcriptHasher != nil {
		panic("transcript hasher must not be set here")
	}
	conn.keys.SuiteID = msgParsed.CipherSuite
	hctx.transcriptHasher = conn.keys.Suite().NewHasher()
	// only after we know ciphersuite, can we now hash ClientHello1
	{
		clientHello1Msg := hctx.generateClientHello(conn, false, conn.tr.opts, false, nil)
		clientHello1Msg.AddToHash(hctx.transcriptHasher)
		debugPrintSum(hctx.transcriptHasher)
	}
	if msgParsed.IsHelloRetryRequest() {
		conn.keys.SendAcks.Reset() // we do not want to ack HRR, and we do not send unencrypted acks anyway
		if !msgParsed.Extensions.CookieSet {
			return dtlserrors.ErrServerHRRMustContainCookie
		}
		if msg.MsgSeq != 0 {
			return dtlserrors.ErrServerHRRMustHaveMsgSeq0
		}
		// [rfc8446:4.4.1] replace initial hello message with its hash if HRR was used
		var initialHelloTranscriptHash ciphersuite.Hash
		initialHelloTranscriptHash.SetSum(hctx.transcriptHasher)
		hctx.transcriptHasher.Reset()

		syntheticMessage := handshake.Message{
			MsgType: handshake.MsgTypeMessageHash,
			MsgSeq:  0, // does not affect transcript hash
			Body:    initialHelloTranscriptHash.GetValue(),
		}
		syntheticMessage.AddToHash(hctx.transcriptHasher)

		msg.AddToHash(hctx.transcriptHasher)

		clientHelloMsg := hctx.generateClientHello(conn, false, conn.tr.opts, true, msgParsed.Extensions.Cookie)
		if err := hctx.PushMessage(conn, clientHelloMsg); err != nil {
			return err
		}
		conn.hctx.serverUsedHRR = true
		conn.stateID = smIDHandshakeClientExpectServerHello
		return nil
	}
	// server decided to skip HRR, this is tricky SM switch, we should carefully test it
	conn.hctx.serverUsedHRR = false
	conn.stateID = smIDHandshakeClientExpectServerHello
	return conn.state().OnServerHello(conn, msg, msgParsed)
}
