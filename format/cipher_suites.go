package format

import (
	"encoding/binary"
	"errors"
)

type CipherSuitesSet struct {
	// All known CypherSuites are represented by those bools, all unknown are skipped
	HasCypherSuite_TLS_AES_128_GCM_SHA256       bool
	HasCypherSuite_TLS_AES_256_GCM_SHA384       bool
	HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 bool
	HasCypherSuite_TLS_AES_128_CCM_SHA256       bool
	HasCypherSuite_TLS_AES_128_CCM_8_SHA256     bool
}

var ErrCipherSuitesSetLengthOdd = errors.New("cipher suites set length odd")

func (msg *CipherSuitesSet) Parse(body []byte) (err error) {
	if len(body)%2 != 0 {
		return ErrCipherSuitesSetLengthOdd
	}
	for offset := 0; offset < len(body); offset += 2 {
		cs := binary.BigEndian.Uint16(body[offset:])
		switch cs { // skip unknown
		case 0x1301:
			msg.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
		case 0x1302:
			msg.HasCypherSuite_TLS_AES_256_GCM_SHA384 = true
		case 0x1303:
			msg.HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 = true
		case 0x1304:
			msg.HasCypherSuite_TLS_AES_128_CCM_SHA256 = true
		case 0x1305:
			msg.HasCypherSuite_TLS_AES_128_CCM_8_SHA256 = true
		}
	}
	return nil
}
