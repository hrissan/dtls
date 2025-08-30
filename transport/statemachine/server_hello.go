// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *Connection) receivedServerHelloFragment(opts *options.TransportOptions, fragment handshake.Fragment, rn record.Number) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return conn.state().OnHandshakeMsgFragment(conn, opts, fragment, rn)
}

func (hctx *handshakeContext) generateClientHello(setCookie bool, ck cookie.Cookie) handshake.Message {
	// [rfc8446:4.1.2] the client MUST send the same ClientHello without modification, except as follows
	clientHello := handshake.MsgClientHello{
		Random: hctx.localRandom,
	}
	clientHello.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
	clientHello.Extensions.SupportedVersionsSet = true
	clientHello.Extensions.SupportedVersions.DTLS_13 = true
	clientHello.Extensions.SupportedGroupsSet = true
	clientHello.Extensions.SupportedGroups.X25519 = true
	clientHello.Extensions.SupportedGroups.SECP256R1 = false
	clientHello.Extensions.SupportedGroups.SECP384R1 = false
	clientHello.Extensions.SupportedGroups.SECP512R1 = false

	// We'd like to postpone ECC until HRR, but wolfssl requires key_share in the first client_hello
	// TODO - offload to separate goroutine
	// TODO - contact wolfssl team?
	clientHello.Extensions.KeyShareSet = true
	clientHello.Extensions.KeyShare.X25519PublicKeySet = true
	copy(clientHello.Extensions.KeyShare.X25519PublicKey[:], hctx.x25519Secret.PublicKey().Bytes())

	// We need signature algorithms to sign and check certificate_verify,
	// so we need to support lots of them.
	// TODO - set only those we actually support
	clientHello.Extensions.SignatureAlgorithmsSet = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP256r1_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP384r1_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.ECDSA_SECP512r1_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PKCS1_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PKCS1_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PKCS1_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_RSAE_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_PSS_SHA512 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_RSAE_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_PSS_SHA384 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_RSAE_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.RSA_PSS_PSS_SHA256 = true
	clientHello.Extensions.SignatureAlgorithms.ED25519 = false
	clientHello.Extensions.SignatureAlgorithms.ED448 = false
	clientHello.Extensions.EncryptThenMacSet = false // not needed in DTLS1.3, but wolf sends it

	if setCookie {
		clientHello.Extensions.CookieSet = true
		clientHello.Extensions.Cookie = ck
	}

	messageBody := clientHello.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeClientHello,
		Body:    messageBody,
	}
}

func IsSupportedServerHello(msgParsed *handshake.MsgServerHello) error {
	if msgParsed.Extensions.SupportedVersions.SelectedVersion != handshake.DTLS_VERSION_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if msgParsed.CipherSuite != ciphersuite.TLS_AES_128_GCM_SHA256 {
		return dtlserrors.ErrParamsSupportCiphersuites
	}
	return nil
}
