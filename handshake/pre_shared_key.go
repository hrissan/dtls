// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/format"
)

var ErrPSKTooManyIdentities = fmt.Errorf("too many identities, only %d is supported", constants.MaxPSKIdentities)
var ErrPSKEmptyIdentity = fmt.Errorf("empty identity")
var ErrPSKBindersMismatch = errors.New("there must be equal number of identities and binders")
var ErrPSKBinderTooLong = errors.New("binder length is larger than implementation supports")

// for now after parsing those slices point to datagram/message,
// so must be copied or discarded immediately after parsing
type PSKIdentity struct {
	Identity []byte // points to external buffer, must be copied/discarded after parsing

	ObfuscatedTicketAge uint32

	// [rfc8446:4.2.11] puts binders in a separate array, so that identities are included into
	// early transcript hash
	Binder []byte // points to external buffer, must be copied/discarded after parsing
}

type PreSharedKey struct {
	Identities     [constants.MaxPSKIdentities]PSKIdentity
	IdentitiesSize int

	SelectedIdentity uint16
}

func (identity *PSKIdentity) parse(body []byte, offset int) (_ int, err error) {
	if offset, identity.Identity, err = format.ParserReadUint16Length(body, offset); err != nil {
		return offset, err
	}
	if offset, identity.ObfuscatedTicketAge, err = format.ParserReadUint32(body, offset); err != nil {
		return offset, err
	}
	return offset, nil
}

func (identity *PSKIdentity) write(body []byte) []byte {
	var mark int
	body, mark = format.MarkUint16Offset(body)
	body = append(body, identity.Identity...)
	format.FillUint16Offset(body, mark)
	body = binary.BigEndian.AppendUint32(body, identity.ObfuscatedTicketAge)
	return body
}

func (msg *PreSharedKey) parseIdentities(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		if msg.IdentitiesSize >= len(msg.Identities) {
			return ErrPSKTooManyIdentities
		}
		if offset, err = msg.Identities[msg.IdentitiesSize].parse(body, offset); err != nil {
			return err
		}
		msg.IdentitiesSize++ // no overflow due to check above
	}
	return nil
}

func (msg *PreSharedKey) writeIdentities(body []byte) []byte {
	for _, identity := range msg.GetIdentities() {
		body = identity.write(body)
	}
	return body
}

func (msg *PreSharedKey) parseBinders(body []byte) (err error) {
	offset := 0
	binderNum := 0
	for ; offset < len(body); binderNum++ {
		var binder []byte
		if offset, binder, err = format.ParserReadByteLength(body, offset); err != nil {
			return err
		}
		if binderNum >= msg.IdentitiesSize {
			return ErrPSKBindersMismatch
		}
		identity := &msg.Identities[binderNum] // no overflow due to check above
		identity.Binder = binder
	}
	if binderNum != msg.IdentitiesSize {
		return ErrPSKBindersMismatch
	}
	return nil
}

func (msg *PreSharedKey) writeBinders(body []byte) []byte {
	var mark int
	for _, identity := range msg.GetIdentities() {
		body, mark = format.MarkByteOffset(body)
		body = append(body, identity.Binder...)
		format.FillByteOffset(body, mark)
	}
	return body
}

func (msg *PreSharedKey) Parse(body []byte, isServerHello bool, bindersListLength *int) (err error) {
	offset := 0
	if isServerHello {
		if offset, msg.SelectedIdentity, err = format.ParserReadUint16(body, offset); err != nil {
			return err
		}
		return format.ParserReadFinish(body, offset)
	}
	var insideBody []byte
	if offset, insideBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseIdentities(insideBody); err != nil {
		return err
	}
	if bindersListLength != nil {
		*bindersListLength = len(body) - offset
	}
	if offset, insideBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseBinders(insideBody); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *PreSharedKey) Write(body []byte, isServerHello bool, bindersListLength *int) []byte {
	if isServerHello {
		body = binary.BigEndian.AppendUint16(body, msg.SelectedIdentity)
		return body
	}
	var externalMark int
	body, externalMark = format.MarkUint16Offset(body)
	body = msg.writeIdentities(body)
	format.FillUint16Offset(body, externalMark)
	body, externalMark = format.MarkUint16Offset(body)
	body = msg.writeBinders(body)
	format.FillUint16Offset(body, externalMark)
	if bindersListLength != nil {
		*bindersListLength = len(body) - externalMark
	}
	return body
}

func (msg *PreSharedKey) GetIdentities() []PSKIdentity {
	return msg.Identities[:msg.IdentitiesSize]
}

func (msg *PreSharedKey) AddIdentity(identity []byte) error {
	if len(identity) == 0 {
		return ErrPSKEmptyIdentity
	}
	if msg.IdentitiesSize >= len(msg.Identities) {
		return ErrPSKTooManyIdentities
	}
	msg.Identities[msg.IdentitiesSize].Identity = identity
	msg.IdentitiesSize++ // no overflow due to check above
	return nil
}
