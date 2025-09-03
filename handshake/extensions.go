// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"encoding/binary"
	"errors"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/format"
	"github.com/hrissan/dtls/safecast"
)

const (
	EXTENSION_SUPPORTED_GROUPS      = 0x000a
	EXTENSION_SIGNATURE_ALGORITHMS  = 0x000d
	EXTENSION_ENCRYPT_THEN_MAC      = 0x0016
	EXTENSION_PRE_SHARED_KEY        = 0x0029
	EXTENSION_EARLY_DATA            = 0x002a
	EXTENSION_SUPPORTED_VERSIONS    = 0x002b
	EXTENSION_COOKIE                = 0x002c
	EXTENSION_PSK_KEY_EXCHANGE_MODE = 0x002d
	EXTENSION_KEY_SHARE             = 0x0033
)

var ErrInvalidEarlyDataIndicationSize = errors.New("invalid EarlyDataIndicationSize")
var ErrPreSharedKeyExtensionMustBeLast = errors.New("psk_key_exchange_modes extension must be last")

// after parsing, slices inside point to datagram, so must not be retained
type ExtensionsSet struct {
	SupportedVersionsSet   bool
	SupportedVersions      SupportedVersions
	SupportedGroupsSet     bool
	SupportedGroups        SupportedGroups
	SignatureAlgorithmsSet bool
	SignatureAlgorithms    SignatureAlgorithms
	EarlyDataSet           bool
	EarlyDataMaxSize       uint32
	EncryptThenMacSet      bool

	CookieSet bool // we do not play with nil values
	Cookie    []byte

	KeyShareSet bool
	KeyShare    KeyShare

	PskExchangeModesSet bool
	PskExchangeModes    PskExchangeModes

	PreSharedKeySet bool
	PreSharedKey    PreSharedKey
}

func (msg *ExtensionsSet) parseCookie(body []byte) (err error) {
	offset := 0
	if offset, msg.Cookie, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *ExtensionsSet) parseInside(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool, bindersListLength *int) (err error) {
	offset := 0
	for offset < len(body) {
		var extensionType uint16
		if offset, extensionType, err = format.ParserReadUint16(body, offset); err != nil {
			return err
		}
		var extensionBody []byte
		if offset, extensionBody, err = format.ParserReadUint16Length(body, offset); err != nil {
			return err
		}
		switch extensionType { // skip unknown/not needed
		case EXTENSION_SUPPORTED_GROUPS:
			if err := msg.SupportedGroups.Parse(extensionBody); err != nil {
				return err
			}
			msg.SupportedGroupsSet = true
		case EXTENSION_SIGNATURE_ALGORITHMS:
			if err := msg.SignatureAlgorithms.Parse(extensionBody); err != nil {
				return err
			}
			msg.SignatureAlgorithmsSet = true
		case EXTENSION_EARLY_DATA: // [rfc8446:4.2.10]
			if isNewSessionTicket {
				if len(extensionBody) != 4 {
					return ErrInvalidEarlyDataIndicationSize
				}
				msg.EarlyDataMaxSize = binary.BigEndian.Uint32(extensionBody)
			} else {
				if len(extensionBody) != 0 {
					return ErrInvalidEarlyDataIndicationSize
				}
			}
			msg.EarlyDataSet = true
		case EXTENSION_SUPPORTED_VERSIONS: // Supported Versions
			if err := msg.SupportedVersions.Parse(extensionBody, isServerHello); err != nil {
				return err
			}
			msg.SupportedVersionsSet = true
		case EXTENSION_COOKIE:
			if err := msg.parseCookie(extensionBody); err != nil {
				return err
			}
			msg.CookieSet = true
		case EXTENSION_KEY_SHARE:
			if err := msg.KeyShare.Parse(extensionBody, isServerHello, isHelloRetryRequest); err != nil {
				return err
			}
			msg.KeyShareSet = true
		case EXTENSION_PSK_KEY_EXCHANGE_MODE:
			if isServerHello {
				// [rfc8446:4.2.9]
				return dtlserrors.ErrServerMustNotSendPSKModes
			}
			if err := msg.PskExchangeModes.Parse(extensionBody); err != nil {
				return err
			}
			msg.PskExchangeModesSet = true
		case EXTENSION_PRE_SHARED_KEY:
			if err := msg.PreSharedKey.Parse(extensionBody, isServerHello, bindersListLength); err != nil {
				return err
			}
			msg.PreSharedKeySet = true
			// "pre_shared_key" must be last [rfc8446:4.2.11] (which MUST be the last extension in the ClientHello)
			if offset != len(body) {
				return ErrPreSharedKeyExtensionMustBeLast
			}
			return nil
		}
	}
	return nil
}

func (msg *ExtensionsSet) Parse(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool, bindersListLength *int) (err error) {
	offset := 0
	var extensionsBody []byte
	if offset, extensionsBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err = msg.parseInside(extensionsBody, isNewSessionTicket, isServerHello, isHelloRetryRequest, bindersListLength); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *ExtensionsSet) WriteInside(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool, bindersListLength *int) []byte {
	var mark int
	if msg.SupportedVersionsSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_SUPPORTED_VERSIONS)
		body, mark = format.MarkUint16Offset(body)
		body = msg.SupportedVersions.Write(body, isServerHello)
		format.FillUint16Offset(body, mark)
	}
	if msg.SupportedGroupsSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_SUPPORTED_GROUPS)
		body, mark = format.MarkUint16Offset(body)
		body = msg.SupportedGroups.Write(body)
		format.FillUint16Offset(body, mark)
	}
	if msg.SignatureAlgorithmsSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_SIGNATURE_ALGORITHMS)
		body, mark = format.MarkUint16Offset(body)
		body = msg.SignatureAlgorithms.Write(body)
		format.FillUint16Offset(body, mark)
	}
	if msg.EarlyDataSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_EARLY_DATA)
		body, mark = format.MarkUint16Offset(body)
		if isNewSessionTicket {
			body = binary.BigEndian.AppendUint32(body, msg.EarlyDataMaxSize)
		}
		format.FillUint16Offset(body, mark)
	}
	if msg.EncryptThenMacSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_ENCRYPT_THEN_MAC)
		body, mark = format.MarkUint16Offset(body)
		format.FillUint16Offset(body, mark)
	}
	if msg.CookieSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_COOKIE)
		body, mark = format.MarkUint16Offset(body)
		body = binary.BigEndian.AppendUint16(body, safecast.Cast[uint16](len(msg.Cookie)))
		body = append(body, msg.Cookie...)
		format.FillUint16Offset(body, mark)
	}
	if msg.KeyShareSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_KEY_SHARE)
		body, mark = format.MarkUint16Offset(body)
		body = msg.KeyShare.Write(body, isServerHello, isHelloRetryRequest)
		format.FillUint16Offset(body, mark)
	}
	if msg.PskExchangeModesSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_PSK_KEY_EXCHANGE_MODE)
		body, mark = format.MarkUint16Offset(body)
		body = msg.PskExchangeModes.Write(body)
		format.FillUint16Offset(body, mark)
	}
	// "pre_shared_key" must be last [rfc8446:4.2.11] (which MUST be the last extension in the ClientHello)
	if msg.PreSharedKeySet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_PRE_SHARED_KEY)
		body, mark = format.MarkUint16Offset(body)
		body = msg.PreSharedKey.Write(body, isServerHello, bindersListLength)
		format.FillUint16Offset(body, mark)
	}
	return body
}

func (msg *ExtensionsSet) Write(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool, bindersListLength *int) []byte {
	body, mark := format.MarkUint16Offset(body)
	body = msg.WriteInside(body, isNewSessionTicket, isServerHello, isHelloRetryRequest, bindersListLength)
	format.FillUint16Offset(body, mark)
	return body
}
