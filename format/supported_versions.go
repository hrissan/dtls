package format

import (
	"encoding/binary"
)

const (
	DTLS_VERSION_12 = 0xFEFD
	DTLS_VERSION_13 = 0xFEFC
)

type SupportedVersionsSet struct {
	DTLS_12 bool
	DTLS_13 bool

	SelectedVersion uint16
}

func (msg *SupportedVersionsSet) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var version uint16
		if offset, version, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		switch version { // skip unknown
		case DTLS_VERSION_12:
			msg.DTLS_12 = true
		case DTLS_VERSION_13:
			msg.DTLS_13 = true
		}
	}
	return nil
}

func (msg *SupportedVersionsSet) Parse(body []byte, isServerHello bool) (err error) {
	offset := 0
	if isServerHello {
		if offset, msg.SelectedVersion, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		return ParserReadFinish(body, offset)
	}
	var insideBody []byte
	if offset, insideBody, err = ParserReadByteLength(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *SupportedVersionsSet) Write(body []byte, isServerHello bool) []byte {
	if isServerHello {
		body = binary.BigEndian.AppendUint16(body, msg.SelectedVersion)
		return body
	}
	body, mark := MarkByteOffset(body)
	if msg.DTLS_12 {
		body = binary.BigEndian.AppendUint16(body, DTLS_VERSION_12)
	}
	if msg.DTLS_13 {
		body = binary.BigEndian.AppendUint16(body, DTLS_VERSION_13)
	}
	FillByteOffset(body, mark)
	return body
}
