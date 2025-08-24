// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"github.com/hrissan/dtls/format"
)

const (
	PSK_Mode_PSK_ONLY = 0
	PSK_Mode_ECDHE    = 1
)

type PskExchangeModes struct {
	PSK_ONLY bool
	ECDHE    bool
}

func (msg *PskExchangeModes) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var mode byte
		if offset, mode, err = format.ParserReadByte(body, offset); err != nil {
			return err
		}
		switch mode { // skip unknown
		case PSK_Mode_PSK_ONLY:
			msg.PSK_ONLY = true
		case PSK_Mode_ECDHE:
			msg.ECDHE = true
		}
	}
	return nil
}

func (msg *PskExchangeModes) Parse(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = format.ParserReadByteLength(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *PskExchangeModes) Write(body []byte) []byte {
	body, mark := format.MarkByteOffset(body)
	if msg.PSK_ONLY {
		body = append(body, PSK_Mode_PSK_ONLY)
	}
	if msg.ECDHE {
		body = append(body, PSK_Mode_ECDHE)
	}
	format.FillByteOffset(body, mark)
	return body
}
