// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

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
	// if conn.hctx.sendQueue.Len() == 0 && conn.keys.Send.Symmetric.Epoch == 2 {
	suite.ComputeSymmetricKeys(&conn.keys.Send.Symmetric, conn.keys.Send.ApplicationTrafficSecret)
	conn.keys.Send.Symmetric.Epoch = 3
	conn.keys.SendNextSegmentSequence = 0
	conn.hctx = nil
	// TODO - why wolf closes connection if we send application data immediately
	// in the same datagram as ack. Reproduce on the latest version of us?
	//conn.handler = &exampleHandler{toSend: "Hello from server\n"}
	conn.stateID = smIDPostHandshake
	conn.handler.OnConnectLocked()
	conn.SignalWriteable()
	// }
	return nil
}
