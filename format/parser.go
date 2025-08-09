package format

import (
	"encoding/binary"
	"errors"
)

var ErrMessageBodyTooShort = errors.New("message body too short")
var ErrMessageBodyExcessBytes = errors.New("client hello excess bytes")

func ParserFinish(body []byte, offset int) error {
	if offset != len(body) {
		return ErrMessageBodyExcessBytes
	}
	return nil
}

func ParserByte(body []byte, offset int) (_ int, value byte, err error) {
	if len(body) < offset+1 {
		return offset, 0, ErrMessageBodyTooShort
	}
	return offset + 1, body[offset], nil
}

func ParserEnsureByte(body []byte, offset int, value byte, err error) (_ int, _ error) {
	if len(body) < offset+1 {
		return offset, ErrMessageBodyTooShort
	}
	if body[offset] != value {
		return offset, err
	}
	return offset + 1, nil
}

func ParserUint16(body []byte, offset int) (_ int, value uint16, err error) {
	if len(body) < offset+2 {
		return offset, 0, ErrMessageBodyTooShort
	}
	return offset + 2, binary.BigEndian.Uint16(body[offset:]), nil
}

func ParserEnsureUint16(body []byte, offset int, value uint16, err error) (_ int, _ error) {
	if len(body) < offset+2 {
		return offset, ErrMessageBodyTooShort
	}
	if binary.BigEndian.Uint16(body[offset:]) != value {
		return offset, err
	}
	return offset + 2, nil
}

func ParserUint16Length(body []byte, offset int) (_ int, value []byte, err error) {
	if len(body) < offset+2 {
		return offset, nil, ErrMessageBodyTooShort
	}
	endOffset := offset + 2 + int(binary.BigEndian.Uint16(body[offset:]))
	if len(body) < endOffset {
		return offset, nil, ErrMessageBodyTooShort
	}
	return endOffset, body[offset+2 : endOffset], nil
}

func ParserCopyBytes(body []byte, offset int, value []byte) (_ int, _ error) {
	if len(body) < offset+len(value) {
		return offset, ErrMessageBodyTooShort
	}
	copy(value, body[offset:])
	return offset + len(value), nil
}
