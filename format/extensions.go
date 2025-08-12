package format

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/hrissan/tinydtls/cookie"
)

const (
	EXTENSION_SUPPORTED_GROUPS     = 0x000a
	EXTENSION_SIGNATURE_ALGORITHMS = 0x000d
	EXTENSION_ENCRYPT_THEN_MAC     = 0x0016
	EXTENSION_EARLY_DATA           = 0x002a
	EXTENSION_SUPPORTED_VERSIONS   = 0x002b
	EXTENSION_COOKIE               = 0x002c
	EXTENSION_KEY_SHARE            = 0x0033
)

var ErrInvalidEarlyDataIndicationSize = errors.New("invalid EarlyDataIndicationSize")

type ExtensionsSet struct {
	SupportedVersionsSet   bool
	SupportedVersions      SupportedVersionsSet
	SupportedGroupsSet     bool
	SupportedGroups        SupportedGroupsSet
	SignatureAlgorithmsSet bool
	SignatureAlgorithms    SignatureAlgorithmsSet
	EarlyDataSet           bool
	EarlyDataMaxSize       uint32
	EncryptThenMacSet      bool

	CookieSet bool
	// we have fixed size cookie to avoid allocations.
	// if actual cookie in datagram is larger or smaller, it will be truncated or padded with zeroes,
	// this makes it invalid for crypto check, which is exactly we want.
	Cookie cookie.Cookie

	KeyShareSet bool
	KeyShare    KeyShareSet // must be last (no idea why). TODO - add link to RFC
}

func (msg *ExtensionsSet) parseCookie(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.Cookie.SetValue(insideBody); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

// TODO - rename to parseInside
func (msg *ExtensionsSet) Parse(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool) (err error) {
	offset := 0
	for offset < len(body) {
		var extensionType uint16
		if offset, extensionType, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		var extensionBody []byte
		if offset, extensionBody, err = ParserReadUint16Length(body, offset); err != nil {
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
		}
	}
	return nil
}

func (msg *ExtensionsSet) ParseOutside(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool) (err error) {
	offset := 0
	var extensionsBody []byte
	if offset, extensionsBody, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err = msg.Parse(extensionsBody, isNewSessionTicket, isServerHello, isHelloRetryRequest); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *ExtensionsSet) Write(body []byte, isNewSessionTicket bool, isServerHello bool, isHelloRetryRequest bool) []byte {
	var mark int
	if msg.SupportedVersionsSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_SUPPORTED_VERSIONS)
		body, mark = MarkUint16Offset(body)
		body = msg.SupportedVersions.Write(body, isServerHello)
		FillUint16Offset(body, mark)
	}
	if msg.SupportedGroupsSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_SUPPORTED_GROUPS)
		body, mark = MarkUint16Offset(body)
		body = msg.SupportedGroups.Write(body)
		FillUint16Offset(body, mark)
	}
	if msg.SignatureAlgorithmsSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_SIGNATURE_ALGORITHMS)
		body, mark = MarkUint16Offset(body)
		body = msg.SignatureAlgorithms.Write(body)
		FillUint16Offset(body, mark)
	}
	if msg.EarlyDataSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_EARLY_DATA)
		body, mark = MarkUint16Offset(body)
		if isNewSessionTicket {
			body = binary.BigEndian.AppendUint32(body, msg.EarlyDataMaxSize)
		}
		FillUint16Offset(body, mark)
	}
	if msg.EncryptThenMacSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_ENCRYPT_THEN_MAC)
		body, mark = MarkUint16Offset(body)
		FillUint16Offset(body, mark)
	}
	if msg.CookieSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_COOKIE)
		body, mark = MarkUint16Offset(body)
		data := msg.Cookie.GetValue()
		if len(data) >= math.MaxUint16 {
			panic("cookie length too big")
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(data)))
		body = append(body, data...)
		FillUint16Offset(body, mark)
	}
	if msg.KeyShareSet {
		body = binary.BigEndian.AppendUint16(body, EXTENSION_KEY_SHARE)
		body, mark = MarkUint16Offset(body)
		body = msg.KeyShare.Write(body, isServerHello, isHelloRetryRequest)
		FillUint16Offset(body, mark)
	}
	return body
}
