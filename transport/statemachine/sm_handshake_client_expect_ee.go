// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
)

type smHandshakeClientExpectEE struct {
	smHandshake
}

func (*smHandshakeClientExpectEE) OnEncryptedExtensions(conn *Connection, msg handshake.Message, msgParsed handshake.ExtensionsSet) error {
	hctx := conn.hctx
	hctx.receivedNextFlight(conn)
	_, hctx.ALPNSelected = conn.tr.opts.FindALPN(msgParsed.ALPN.GetProtocols())
	if !conn.tr.opts.ALPNContinueOnMismatch && len(hctx.ALPNSelected) == 0 {
		return dtlserrors.ErrALPNNoCompatibleProtocol
	}
	if conn.hctx.pskSelected {
		conn.stateID = smIDHandshakeClientExpectFinished
	} else {
		conn.stateID = smIDHandshakeClientExpectCert
	}
	return nil
}
