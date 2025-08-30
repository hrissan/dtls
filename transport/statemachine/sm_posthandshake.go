// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

type smPostHandshake struct{}

func (*smPostHandshake) OnHandshakeMsgFragment(conn *Connection, opts *options.TransportOptions,
	fragment handshake.Fragment, rn record.Number) error {
	if fragment.Header.MsgSeq < conn.nextMessageSeqReceive {
		// all messages before were processed by us in the state we already do not remember,
		// so we must acknowledge unconditionally and do nothing.
		conn.keys.AddAck(rn)
		return nil
	}
	if fragment.Header.MsgSeq > conn.nextMessageSeqReceive {
		return nil // no message queue post hondshake, ignore
	}
	if fragment.Header.IsFragmented() {
		// we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		return dtlserrors.WarnPostHandshakeMessageFragmented
	}
	switch fragment.Header.MsgType {
	case handshake.MsgTypeClientHello:
		panic("TODO - should not be called, client_hello is special")
	case handshake.MsgTypeNewSessionTicket:
		return conn.receivedNewSessionTicket(opts, fragment, rn)
	case handshake.MsgTypeKeyUpdate:
		return conn.receivedKeyUpdate(opts, fragment, rn)
	}
	return dtlserrors.ErrHandshakeMessagePostHandshake
}

func (*smPostHandshake) OnServerHello(conn *Connection, msg handshake.Message, msgParsed handshake.MsgServerHello) error {
	panic("implement or remove")
}

func (*smPostHandshake) OnEncryptedExtensions(conn *Connection, msg handshake.Message, msgParsed handshake.ExtensionsSet) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}

func (*smPostHandshake) OnCertificate(conn *Connection, msg handshake.Message, msgParsed handshake.MsgCertificate) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}

func (*smPostHandshake) OnCertificateVerify(conn *Connection, msg handshake.Message, msgParsed handshake.MsgCertificateVerify) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}

func (*smPostHandshake) OnFinished(conn *Connection, msg handshake.Message, msgParsed handshake.MsgFinished) error {
	panic("unreachable due to check in OnHandshakeMsgFragment")
}
