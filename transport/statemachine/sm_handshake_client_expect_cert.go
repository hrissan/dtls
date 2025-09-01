// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectCert struct {
	smHandshake
}

func (*smHandshakeClientExpectCert) OnCertificate(conn *Connection, msg handshake.Message, msgParsed handshake.MsgCertificate) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	hctx.certificateChain = msgParsed
	conn.stateID = smIDHandshakeClientExpectCertVerify
	return nil
}
