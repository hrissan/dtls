package format

import "errors"

type ClientHello struct {
	// ProtocolVersion is checked but not stored
	Random [32]byte
	// legacy_session_id is checked but not stored
	// legacy_cookie is checked but not stored
	CypherSuites []uint16 // TODO - fixed size
	// legacy_compression_methods is checked but not stored
	Extension []byte
}

func (msg *ClientHello) MessageName() string {
	return "client_hello"
}

var ErrClientHelloTooShort = errors.New("client hello too short")
var ErrClientHelloLegacyVersion = errors.New("client hello wrong legacy version")
var ErrClientHelloLegacySessionCookie = errors.New("client hello wrong legacy session or cookie")
var ErrClientHelloExcessBytes = errors.New("client hello excess bytes")

func (msg *ClientHello) Parse(body []byte) error {
	if len(body) < 36 {
		return ErrClientHelloTooShort
	}
	if body[0] != 254 || body[1] != 253 {
		return ErrClientHelloLegacyVersion
	}
	copy(msg.Random[:], body[2:2+32])
	if body[34] != 0 || body[35] != 0 {
		return ErrClientHelloLegacySessionCookie
	}
	offset := 36
	// TODO - parse cipher_suites
	// TODO - parse legacy_compression_methods
	// TODO - parse extensions
	if offset != len(body) {
		return ErrClientHelloExcessBytes
	}
	return nil
}
