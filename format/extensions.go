package format

import (
	"encoding/binary"
	"errors"
)

var ErrInvalidEarlyDataIndicationSize = errors.New("invalid EarlyDataIndicationSize")

type ExtensionsSet struct {
	SupportedVersions   SupportedVersionsSet
	SupportedGroups     SupportedGroupsSet
	SignatureAlgorithms SignatureAlgorithmsSet
	KeyShare            KeyShareSet
	EarlyDataSet        bool
	EarlyDataMaxSize    uint32

	CookieSet bool
	Cookie    []byte // warning - alias of datagram bytes, must not be retained
}

func (msg *ExtensionsSet) parseCookie(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = ParserReadByteLength(body, offset); err != nil {
		return err
	}
	msg.CookieSet = true
	msg.Cookie = insideBody
	return ParserReadFinish(body, offset)
}

func (msg *ExtensionsSet) Parse(body []byte, isNewSessionTicket bool) (err error) {
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
		case 0x000a: // Supported Groups
			if err := msg.SupportedGroups.Parse(extensionBody); err != nil {
				return err
			}
		case 0x000d: // Signature Algorithms
			if err := msg.SignatureAlgorithms.Parse(extensionBody); err != nil {
				return err
			}
		case 0x002a: // Early Data Indicator [rfc8446:4.2.10]
			msg.EarlyDataSet = true
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
		case 0x002b: // Supported Versions
			if err := msg.SupportedVersions.Parse(extensionBody); err != nil {
				return err
			}
		case 0x002c: // Cookie
			if err := msg.parseCookie(extensionBody); err != nil {
				return err
			}
		case 0x0033: // Key Share
			if err := msg.KeyShare.Parse(extensionBody); err != nil {
				return err
			}
		}
	}
	return nil
}

func (msg *ExtensionsSet) Write(body []byte, isNewSessionTicket bool) []byte {
	return body
}
