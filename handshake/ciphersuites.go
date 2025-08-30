// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"encoding/binary"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/format"
)

type CipherSuitesSet struct {
	// each known CipherSuite is represented by a bool, all unknown are skipped
	HasCypherSuite_TLS_AES_128_GCM_SHA256       bool
	HasCypherSuite_TLS_AES_256_GCM_SHA384       bool
	HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 bool
	HasCypherSuite_TLS_AES_128_CCM_SHA256       bool
	HasCypherSuite_TLS_AES_128_CCM_8_SHA256     bool
}

func (msg *CipherSuitesSet) Parse(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var cipherSuite uint16
		if offset, cipherSuite, err = format.ParserReadUint16(body, offset); err != nil {
			return err
		}
		switch ciphersuite.ID(cipherSuite) { // skip unknown
		case ciphersuite.TLS_AES_128_GCM_SHA256:
			msg.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
		case ciphersuite.TLS_AES_256_GCM_SHA384:
			msg.HasCypherSuite_TLS_AES_256_GCM_SHA384 = true
		case ciphersuite.TLS_CHACHA20_POLY1305_SHA256:
			msg.HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 = true
		case ciphersuite.TLS_AES_128_CCM_SHA256:
			msg.HasCypherSuite_TLS_AES_128_CCM_SHA256 = true
		case ciphersuite.TLS_AES_128_CCM_8_SHA256:
			msg.HasCypherSuite_TLS_AES_128_CCM_8_SHA256 = true
		}
	}
	return nil
}

func (msg *CipherSuitesSet) Write(body []byte) []byte {
	if msg.HasCypherSuite_TLS_AES_128_GCM_SHA256 {
		body = binary.BigEndian.AppendUint16(body, uint16(ciphersuite.TLS_AES_128_GCM_SHA256))
	}
	if msg.HasCypherSuite_TLS_AES_256_GCM_SHA384 {
		body = binary.BigEndian.AppendUint16(body, uint16(ciphersuite.TLS_AES_256_GCM_SHA384))
	}
	if msg.HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 {
		body = binary.BigEndian.AppendUint16(body, uint16(ciphersuite.TLS_CHACHA20_POLY1305_SHA256))
	}
	if msg.HasCypherSuite_TLS_AES_128_CCM_SHA256 {
		body = binary.BigEndian.AppendUint16(body, uint16(ciphersuite.TLS_AES_128_CCM_SHA256))
	}
	if msg.HasCypherSuite_TLS_AES_128_CCM_8_SHA256 {
		body = binary.BigEndian.AppendUint16(body, uint16(ciphersuite.TLS_AES_128_CCM_8_SHA256))
	}
	return body
}
