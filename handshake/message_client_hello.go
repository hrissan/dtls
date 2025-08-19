package handshake

import (
	"encoding/binary"
	"errors"

	"github.com/hrissan/tinydtls/format"
)

var ErrClientHelloLegacyVersion = errors.New("client hello wrong legacy version")
var ErrClientHelloLegacySessionCookie = errors.New("client hello wrong legacy session or cookie")
var ErrClientHelloLegacyCompressionMethod = errors.New("client hello wrong legacy compression method")

type MsgClientHello struct {
	// ProtocolVersion is checked but not stored
	Random [32]byte
	// legacy_session_id is checked but not stored
	// legacy_cookie is checked but not stored
	CipherSuites CipherSuitesSet
	// legacy_compression_methods is checked but not stored
	Extensions ExtensionsSet
}

func (msg *MsgClientHello) MessageKind() string { return "handshake" }
func (msg *MsgClientHello) MessageName() string { return "ClientHello" }

func (msg *MsgClientHello) Parse(body []byte) (err error) {
	offset := 0
	if offset, err = format.ParserReadUint16Const(body, offset, 0xFEFD, ErrClientHelloLegacyVersion); err != nil {
		return err
	}
	if offset, err = format.ParserReadFixedBytes(body, offset, msg.Random[:]); err != nil {
		return err
	}
	if offset, err = format.ParserReadUint16Const(body, offset, 0, ErrClientHelloLegacySessionCookie); err != nil {
		return err
	}
	var cipherSuitesBody []byte
	if offset, cipherSuitesBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err = msg.CipherSuites.Parse(cipherSuitesBody); err != nil {
		return err
	}
	if offset, err = format.ParserReadUint16Const(body, offset, 0x0100, ErrClientHelloLegacyCompressionMethod); err != nil {
		return err
	}
	var extensionsBody []byte
	if offset, extensionsBody, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err = msg.Extensions.Parse(extensionsBody, false, false, false); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *MsgClientHello) Write(body []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, 0xFEFD)

	body = append(body, msg.Random[:]...)

	body = binary.BigEndian.AppendUint16(body, 0) // legacy_session_id, legacy_cookie

	body, mark := format.MarkUint16Offset(body)
	body = msg.CipherSuites.Write(body)
	format.FillUint16Offset(body, mark)

	body = binary.BigEndian.AppendUint16(body, 0x0100) // legacy_compression_methods

	body, mark = format.MarkUint16Offset(body)
	body = msg.Extensions.WriteInside(body, false, false, false)
	format.FillUint16Offset(body, mark)

	return body
}
