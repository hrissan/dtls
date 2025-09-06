// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
)

type smHandshake struct {
	smClosed
}

func (*smHandshake) OnHandshakeMsgFragment(conn *Connection, opts *Options,
	fragment handshake.Fragment, rn record.Number) error {

	if fragment.Header.MsgSeq < conn.hctx.firstMessageSeqInReceiveQueue(conn) {
		// all messages before were processed by us in the state we already do not remember,
		// so we must acknowledge unconditionally and do nothing.
		conn.keys.AddAck(rn)
		return nil
	}
	switch fragment.Header.MsgType {
	case handshake.MsgTypeClientHello:
		panic("TODO - should not be called, client_hello is special")
	case handshake.MsgTypeNewSessionTicket:
	case handshake.MsgTypeKeyUpdate:
		// we must never add post-handshake messages to received messages queue in Handshake,
		// because we could partially acknowledge them, so later when we need to destroy conn.Handshake,
		// we will not be able to throw them out (peer will never send fragments again), and we will not
		// be able to process them immediately.
		if fragment.Header.MsgSeq == conn.hctx.firstMessageSeqInReceiveQueue(conn) {
			return dtlserrors.ErrPostHandshakeMessageDuringHandshake
		}
		// if not the first message, simply do not acknowledge and wait for the first message to be received
		return nil
	}
	return conn.hctx.ReceivedFragment(conn, fragment, rn)
}
