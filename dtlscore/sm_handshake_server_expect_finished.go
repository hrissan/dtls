// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
)

type smHandshakeServerExpectFinished struct {
	smHandshake
}

func (*smHandshakeServerExpectFinished) OnFinished(conn *Connection, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	hctx := conn.hctx
	suite := conn.keys.Suite()
	hctx.receivedNextFlight(conn)
	// [rfc8446:4.4.4] - finished
	var finishedTranscriptHash ciphersuite.Hash
	finishedTranscriptHash.SetSum(hctx.transcriptHasher)

	mustBeFinished := keys.ComputeFinished(suite, hctx.handshakeTrafficSecretReceive, finishedTranscriptHash)
	if string(msgParsed.VerifyData) != string(mustBeFinished.GetValue()) {
		return dtlserrors.ErrFinishedMessageVerificationFailed
	}
	fmt.Printf("finished message verify ok: %+v\n", msgParsed)

	if conn.keys.ReceiveEpoch != 2 { // should be [2] [.] or [1] [2] here
		panic("unexpected receive epoch here")
	}
	conn.removeOldReceiveKeys()
	if err := conn.generateNewReceiveKeys(); err != nil {
		panic("we must be able to generate new keys receive here")
	}

	alpnSelected := conn.hctx.ALPNSelected
	conn.hctx = nil
	conn.debugPrintKeys()
	// TODO - why wolf closes connection if we send application data immediately
	// in the same datagram as ack. Reproduce on the latest version of us?
	conn.stateID = smIDPostHandshake
	conn.handler.OnHandshakeLocked(HandshakeInfo{ALPNSelected: alpnSelected})
	conn.SignalWriteable()
	return nil
}
