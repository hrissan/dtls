package format

import "encoding/binary"

const (
	SupportedGroup_X25519    = 0x001D
	SupportedGroup_SECP256R1 = 0x0017
	SupportedGroup_SECP384R1 = 0x0018
	SupportedGroup_SECP521R1 = 0x0019
	SupportedGroup_X448      = 0x001E
)

type SupportedGroupsSet struct {
	X25519    bool
	SECP256R1 bool
	SECP384R1 bool
	SECP521R1 bool
	X448      bool
}

func (msg *SupportedGroupsSet) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var version uint16
		if offset, version, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		switch version { // skip unknown
		case SupportedGroup_X25519:
			msg.X25519 = true
		case SupportedGroup_SECP256R1:
			msg.SECP256R1 = true
		case SupportedGroup_SECP384R1:
			msg.SECP384R1 = true
		case SupportedGroup_SECP521R1:
			msg.SECP521R1 = true
		case SupportedGroup_X448:
			msg.X448 = true
		}
	}
	return nil
}

func (msg *SupportedGroupsSet) Parse(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *SupportedGroupsSet) Write(body []byte) []byte {
	body, mark := MarkUin16Offset(body)
	if msg.X25519 {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_X25519)
	}
	if msg.SECP256R1 {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_SECP256R1)
	}
	if msg.SECP384R1 {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_SECP384R1)
	}
	if msg.SECP521R1 {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_SECP521R1)
	}
	if msg.X448 {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_X448)
	}
	FillUin16Offset(body, mark)
	return body
}
