// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectEE struct {
	smHandshake
}

func (*smHandshakeClientExpectEE) OnEncryptedExtensions(conn *ConnectionImpl, msg handshake.Message, msgParsed handshake.ExtensionsSet) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	conn.stateID = smIDHandshakeClientExpectServerCert
	return nil
}
