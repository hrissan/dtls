// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"errors"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/format"
)

// after parsing, slices inside point to datagram, so must not be retained
type ALPN struct {
	ProtocolsLength int
	Protocols       [constants.MaxALPNProtocolsLength][]byte
}

var ErrALPNTooManyProtocols = errors.New("too many ALPN protocols supplied")
var ErrALPNEmptyProtocol = errors.New("empty ALPN protocol forbidden")
var ErrALPNMustBeSingleProtocol = errors.New("server must select a single ALPN protocol")

func (msg *ALPN) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		if msg.ProtocolsLength >= len(msg.Protocols) {
			return ErrALPNTooManyProtocols
		}
		if offset, msg.Protocols[msg.ProtocolsLength], err = format.ParserReadByteLength(body, offset); err != nil {
			return err
		}
		if len(msg.Protocols[msg.ProtocolsLength]) == 0 {
			return ErrALPNEmptyProtocol
		}
		msg.ProtocolsLength++ // no overflow due to check above
	}

	return nil
}

func (msg *ALPN) Parse(body []byte, isServerHello bool) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	if isServerHello && msg.ProtocolsLength != 1 {
		return ErrALPNMustBeSingleProtocol
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *ALPN) Write(body []byte, isServerHello bool) []byte {
	var mark int
	if isServerHello && msg.ProtocolsLength != 1 {
		panic(ErrALPNMustBeSingleProtocol.Error())
	}
	body, externalMark := format.MarkUint16Offset(body)
	for _, protocol := range msg.GetProtocols() {
		body, mark = format.MarkByteOffset(body)
		body = append(body, protocol...)
		format.FillByteOffset(body, mark)
	}
	format.FillUint16Offset(body, externalMark)
	return body
}

func (msg *ALPN) GetProtocols() [][]byte {
	return msg.Protocols[:msg.ProtocolsLength]
}

func (msg *ALPN) AddProtocol(protocol []byte) error {
	if len(protocol) == 0 {
		return ErrALPNEmptyProtocol
	}
	if msg.ProtocolsLength >= len(msg.Protocols) {
		return ErrALPNTooManyProtocols
	}
	msg.Protocols[msg.ProtocolsLength] = protocol
	msg.ProtocolsLength++
	return nil
}
