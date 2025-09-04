// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *Connection) receivedServerHelloFragment(opts *options.TransportOptions, fragment handshake.Fragment, rn record.Number) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return conn.state().OnHandshakeMsgFragment(conn, opts, fragment, rn)
}

func (hctx *handshakeContext) generateClientHello(opts *options.TransportOptions, setCookie bool, ck []byte) handshake.Message {
	// [rfc8446:4.1.2] the client MUST send the same ClientHello without modification, except as follows
	clientHello := handshake.MsgClientHello{
		Random: hctx.localRandom,
	}
	clientHello.CipherSuites.HasCypherSuite_TLS_AES_128_GCM_SHA256 = opts.TLS_AES_128_GCM_SHA256
	clientHello.CipherSuites.HasCypherSuite_TLS_AES_256_GCM_SHA384 = opts.TLS_AES_256_GCM_SHA384
	clientHello.CipherSuites.HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 = opts.TLS_CHACHA20_POLY1305_SHA256
	clientHello.Extensions.SupportedVersionsSet = true
	clientHello.Extensions.SupportedVersions.DTLS_13 = true
	clientHello.Extensions.SupportedGroupsSet = true
	clientHello.Extensions.SupportedGroups.X25519 = true
	clientHello.Extensions.SupportedGroups.SECP256R1 = false
	clientHello.Extensions.SupportedGroups.SECP384R1 = false
	clientHello.Extensions.SupportedGroups.SECP512R1 = false

	suite := ciphersuite.GetSuite(ciphersuite.TLS_AES_128_GCM_SHA256) // TODO - negotiate suites, but how?
	emptyHash := suite.EmptyHash()                                    // Binder[] byte slices point here to avoid allocations
	if len(opts.PSKClientIdentities) != 0 && opts.PSKAppendSecret != nil {
		clientHello.Extensions.PreSharedKeySet = true

		clientHello.Extensions.PskExchangeModesSet = true
		clientHello.Extensions.PskExchangeModes.ECDHE = true

		for _, name := range opts.PSKClientIdentities {
			identity := handshake.PSKIdentity{
				Identity:            name,
				ObfuscatedTicketAge: 0,
				Binder:              emptyHash.GetValue(), // any value is OK, we only need correct size of ClientHello
			}
			if err := clientHello.Extensions.PreSharedKey.AddIdentity(identity); err != nil {
				panic("error adding client PSK identity: " + err.Error()) // TODO - return error
			}
		}
		clientHello.Extensions.EarlyDataSet = true
	}

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

	var bindersListLength int
	messageBody := clientHello.Write(nil, &bindersListLength) // TODO - reuse message bodies in a rope

	msgClientHello := handshake.Message{
		MsgType: handshake.MsgTypeClientHello,
		Body:    messageBody,
	}

	if !clientHello.Extensions.PreSharedKeySet {
		return msgClientHello
	}

	transcriptHasher := suite.NewHasher()

	partialHash := msgClientHello.AddToHashPartial(transcriptHasher, bindersListLength)
	// fmt.Printf("partial hash for len=%d %x\n", bindersListLength, partialHash.GetValue())
	// debugPrintSum(transcriptHasher)

	var pskStorage [256]byte
	var binders [constants.MaxPSKIdentities]ciphersuite.Hash // Binder[] byte slices point here to avoid allocations
	for num, identity := range clientHello.Extensions.PreSharedKey.GetIdentities() {
		psk := opts.PSKAppendSecret(identity.Identity, pskStorage[:0]) // allocates if secret very long
		if len(psk) == 0 {
			panic("empty PSH is prohibited on client") // TODO - return error
		}
		earlySecret := keys.ComputeEarlySecret(suite, psk)
		hmacEarlySecret := suite.NewHMAC(earlySecret.GetValue())
		binderKey := keys.DeriveSecret(hmacEarlySecret, "ext binder", suite.EmptyHash())
		binders[num] = keys.ComputeFinished(suite, binderKey, partialHash)
		clientHello.Extensions.PreSharedKey.Identities[num].Binder = binders[num].GetValue()
		fmt.Printf("PSK binder calculated, identity num=%d identity=%q binder=%x\n", num, identity.Identity, binders[num].GetValue())
	}

	var bindersListLength2 int
	messageBody = clientHello.Write(messageBody[:0], &bindersListLength2) // TODO - reuse message bodies in a rope

	msgClientHello = handshake.Message{
		MsgType: handshake.MsgTypeClientHello,
		Body:    messageBody,
	}

	// transcriptHasher = suite.NewHasher()
	// partialHash = msgClientHello.AddToHashPartial(transcriptHasher, bindersListLength2)
	// fmt.Printf("partial hash for len=%d %x\n", bindersListLength2, partialHash.GetValue())
	// fmt.Printf("message body %x\n", messageBody)
	// debugPrintSum(transcriptHasher)

	return msgClientHello
}

func (tr *Transport) IsSupportedServerHello(msgParsed *handshake.MsgServerHello) error {
	if msgParsed.Extensions.SupportedVersions.SelectedVersion != handshake.DTLS_VERSION_13 {
		return dtlserrors.ErrParamsSupportOnlyDTLS13
	}
	if msgParsed.CipherSuite == ciphersuite.TLS_AES_128_GCM_SHA256 && tr.opts.TLS_AES_128_GCM_SHA256 {
		return nil
	}
	if msgParsed.CipherSuite == ciphersuite.TLS_AES_256_GCM_SHA384 && tr.opts.TLS_AES_256_GCM_SHA384 {
		return nil
	}
	if msgParsed.CipherSuite == ciphersuite.TLS_CHACHA20_POLY1305_SHA256 && tr.opts.TLS_CHACHA20_POLY1305_SHA256 {
		return nil
	}
	return dtlserrors.ErrParamsSupportCiphersuites
}
