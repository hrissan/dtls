package format

import (
	"encoding/binary"
	"errors"
)

var ErrServerHelloLegacyVersion = errors.New("server hello wrong legacy version")
var ErrServerHelloLegacySession = errors.New("server hello wrong legacy session")
var ErrServerHelloLegacyCompressionMethod = errors.New("server hello wrong legacy compression method")

type ServerHello struct {
	// ProtocolVersion is checked but not stored
	Random [32]byte
	// legacy_session_id is checked but not stored
	CipherSuite uint16
	// legacy_compression_methods is checked but not stored
	Extensions ExtensionsSet
}

func (msg *ServerHello) MessageKind() string { return "handshake" }
func (msg *ServerHello) MessageName() string { return "server_hello" }

func (msg *ServerHello) SetHelloRetryRequest() {
	msg.Random = [32]byte{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}
}

func (msg *ServerHello) IsHelloRetryRequest() bool {
	return msg.Random == [32]byte{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}
}

func (msg *ServerHello) Parse(body []byte) (err error) {
	offset := 0
	if offset, err = ParserReadUint16Const(body, offset, 0xFEFD, ErrServerHelloLegacyVersion); err != nil {
		return err
	}
	if offset, err = ParserReadFixedBytes(body, offset, msg.Random[:]); err != nil {
		return err
	}
	if offset, err = ParserReadByteConst(body, offset, 0, ErrServerHelloLegacySession); err != nil {
		return err
	}
	if offset, msg.CipherSuite, err = ParserReadUint16(body, offset); err != nil {
		return err
	}
	if offset, err = ParserReadByteConst(body, offset, 0, ErrServerHelloLegacyCompressionMethod); err != nil {
		return err
	}
	var extensionsBody []byte
	if offset, extensionsBody, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err = msg.Extensions.Parse(extensionsBody, false, true, msg.IsHelloRetryRequest()); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *ServerHello) Write(body []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, 0xFEFD)
	body = append(body, msg.Random[:]...)
	body = append(body, 0) // legacy_session_id
	body = binary.BigEndian.AppendUint16(body, msg.CipherSuite)
	body = append(body, 0) // legacy_compression_methods
	body, mark := MarkUint16Offset(body)
	body = msg.Extensions.Write(body, false, true, msg.IsHelloRetryRequest())
	FillUint16Offset(body, mark)
	return body
}
