package format

import (
	"errors"
)

var ErrClientHelloTooShort = errors.New("client hello too short")
var ErrClientHelloLegacyVersion = errors.New("client hello wrong legacy version")
var ErrClientHelloLegacySessionCookie = errors.New("client hello wrong legacy session or cookie")
var ErrClientHelloLegacyCompressionMethod = errors.New("client hello wrong legacy compression method")

type ClientHello struct {
	// ProtocolVersion is checked but not stored
	Random [32]byte
	// legacy_session_id is checked but not stored
	// legacy_cookie is checked but not stored
	CipherSuites CipherSuitesSet
	// legacy_compression_methods is checked but not stored
	Extension []byte // TODO - fixed size
}

func (msg *ClientHello) MessageKind() string { return "handshake" }
func (msg *ClientHello) MessageName() string { return "client_hello" }

func (msg *ClientHello) Parse(body []byte) (err error) {
	offset := 0
	if offset, err = ParserEnsureUint16(body, offset, 0xFEFD, ErrClientHelloLegacyVersion); err != nil {
		return err
	}
	if offset, err = ParserCopyBytes(body, offset, msg.Random[:]); err != nil {
		return err
	}
	if offset, err = ParserEnsureUint16(body, offset, 0, ErrClientHelloLegacySessionCookie); err != nil {
		return err
	}
	offset, cipherSuitesBody, err := ParserUint16Length(body, offset)
	if err != nil {
		return err
	}
	if err = msg.CipherSuites.Parse(cipherSuitesBody); err != nil {
		return err
	}
	if offset, err = ParserEnsureUint16(body, offset, 0x0100, ErrClientHelloLegacyCompressionMethod); err != nil {
		return err
	}
	offset, extensionsBody, err := ParserUint16Length(body, offset)
	if err != nil {
		return err
	}
	msg.Extension = extensionsBody
	return ParserFinish(body, offset)
}
