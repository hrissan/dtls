// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectServerHRR struct {
	smHandshake
}

func (*smHandshakeClientExpectServerHRR) OnServerHello(conn *Connection, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	if err := IsSupportedServerHello(&msgParsed); err != nil {
		return err
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
		var initialHelloTranscriptHashStorage [constants.MaxHashLength]byte
		initialHelloTranscriptHash := hctx.transcriptHasher.Sum(initialHelloTranscriptHashStorage[:0])
		hctx.transcriptHasher.Reset()
		syntheticHashData := []byte{byte(handshake.MsgTypeMessageHash), 0, 0, byte(len(initialHelloTranscriptHash))}
		_, _ = hctx.transcriptHasher.Write(syntheticHashData)
		_, _ = hctx.transcriptHasher.Write(initialHelloTranscriptHash)

		msg.AddToHash(hctx.transcriptHasher)

		clientHelloMsg := hctx.generateClientHello(true, msgParsed.Extensions.Cookie)
		if err := hctx.PushMessage(conn, clientHelloMsg); err != nil {
			return err
		}
		conn.hctx.serverUsedHRR = true
		conn.stateID = smIDHandshakeClientExpectServerHello
		return nil
	}
	// server decided to skip HRR, this is tricky SM switch, we should carefully test it
	conn.hctx.serverUsedHRR = false
	conn.keys.SuiteID = ciphersuite.TLS_AES_128_GCM_SHA256
	conn.stateID = smIDHandshakeClientExpectServerHello
	return conn.state().OnServerHello(conn, msg, msgParsed)
}
