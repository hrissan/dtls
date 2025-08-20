// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"errors"

	"github.com/hrissan/dtls/format"
)

var ErrKeyUpdateRequestInvalid = errors.New("KeyUpdate request_update invalid value")

type MsgKeyUpdate struct {
	UpdateRequested bool
}

func (msg *MsgKeyUpdate) MessageKind() string { return "handshake" }
func (msg *MsgKeyUpdate) MessageName() string { return "KeyUpdate" }

func (msg *MsgKeyUpdate) Parse(body []byte) (err error) {
	var offset int
	var requestUpdate byte
	if offset, requestUpdate, err = format.ParserReadByte(body, offset); err != nil {
		return err
	}
	switch requestUpdate {
	case 0:
		msg.UpdateRequested = false
	case 1:
		msg.UpdateRequested = true
	default:
		return ErrKeyUpdateRequestInvalid
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *MsgKeyUpdate) Write(body []byte) []byte {
	if msg.UpdateRequested {
		return append(body, 1)
	}
	return append(body, 0)
}
