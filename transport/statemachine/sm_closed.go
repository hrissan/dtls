// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

type smClosed struct{}

func (*smClosed) OnHandshakeMsgFragment(conn *Connection, opts *options.TransportOptions,
	fragment handshake.Fragment, rn record.Number) error {
	return dtlserrors.ErrUnexpectedMessage
}

func (*smClosed) OnServerHello(conn *Connection, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	return dtlserrors.ErrUnexpectedMessage
}

func (*smClosed) OnEncryptedExtensions(conn *Connection, msg handshake.Message, msgParsed handshake.ExtensionsSet) error {
	return dtlserrors.ErrUnexpectedMessage
}

func (*smClosed) OnCertificate(conn *Connection, msg handshake.Message, msgParsed handshake.MsgCertificate) error {
	return dtlserrors.ErrUnexpectedMessage
}

func (*smClosed) OnCertificateVerify(conn *Connection, msg handshake.Message, msgParsed handshake.MsgCertificateVerify) error {
	return dtlserrors.ErrUnexpectedMessage
}

func (*smClosed) OnFinished(conn *Connection, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	return dtlserrors.ErrUnexpectedMessage
}
