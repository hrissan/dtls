// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/replay"
	"github.com/hrissan/dtls/safecast"
)

type partialHandshakeMsg struct {
	Msg handshake.Message
	Ass replay.Assembler
}

func partialHandshakeMsgFull(msg handshake.Message) partialHandshakeMsg {
	p := partialHandshakeMsg{Msg: msg}
	p.Ass.ResetToFull(safecast.Cast[uint32](len(msg.Body)))
	return p
}
