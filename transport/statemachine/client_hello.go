// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"log"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/signature"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *ConnectionImpl) ReceivedClientHello2(opts *options.TransportOptions,
	msg handshake.Message, msgClientHello handshake.MsgClientHello,
	params cookie.Params) error {

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if err := conn.State().OnClientHello2(conn, opts, msg, msgClientHello, params); err != nil {
		return err // TODO - close connection here
	}
	return nil
}

func debugPrintSum(hasher hash.Hash) {
	var ha [constants.MaxHashLength]byte
	hasher.Sum(ha[:0])
	log.Printf("%x\n", ha[:])
}

// we must generate the same server hello, because we are stateless, but this message is in transcript
// TODO - pass selected parameters here from receiver
func GenerateStatelessHRR(datagram []byte, ck cookie.Cookie, keyShareSet bool) ([]byte, []byte) {
	helloRetryRequest := handshake.MsgServerHello{
		CipherSuite: handshake.CypherSuite_TLS_AES_128_GCM_SHA256,
	}
	helloRetryRequest.SetHelloRetryRequest()
	helloRetryRequest.Extensions.SupportedVersionsSet = true
	helloRetryRequest.Extensions.SupportedVersions.SelectedVersion = handshake.DTLS_VERSION_13
	if keyShareSet {
		helloRetryRequest.Extensions.KeyShareSet = true
		helloRetryRequest.Extensions.KeyShare.KeyShareHRRSelectedGroup = handshake.SupportedGroup_X25519
	}
	helloRetryRequest.Extensions.CookieSet = true
	helloRetryRequest.Extensions.Cookie = ck
	recordHdr := record.PlaintextHeader{
		ContentType:    record.RecordTypeHandshake,
		SequenceNumber: 0,
	}
	// first reserve space for headers by writing with not all variables set
	datagram = append(datagram, make([]byte, record.PlaintextRecordHeaderSize+handshake.FragmentHeaderSize)...) // reserve space
	datagram = helloRetryRequest.Write(datagram)
	msgBody := datagram[record.PlaintextRecordHeaderSize+handshake.FragmentHeaderSize:]

	// now overwrite reserved space
	da := recordHdr.Write(datagram[:0], handshake.FragmentHeaderSize+len(msgBody))

	msgHeader := handshake.FragmentHeader{
		MsgType: handshake.MsgTypeServerHello,
		Length:  uint32(len(msgBody)),
		FragmentInfo: handshake.FragmentInfo{
			MsgSeq:         0,
			FragmentOffset: 0,
			FragmentLength: uint32(len(msgBody)),
		},
	}

	_ = msgHeader.Write(da)
	return datagram, msgBody
}

func generateEncryptedExtensions() handshake.Message {
	ee := handshake.ExtensionsSet{
		SupportedGroupsSet: true,
	}
	ee.SupportedGroups.SECP256R1 = true
	ee.SupportedGroups.SECP384R1 = true
	ee.SupportedGroups.SECP512R1 = true
	ee.SupportedGroups.X25519 = true

	messageBody := ee.Write(nil, false, false, false) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeEncryptedExtensions,
		Body:    messageBody,
	}
}

func generateServerCertificate(opts *options.TransportOptions) handshake.Message {
	msg := handshake.MsgCertificate{
		CertificatesLength: len(opts.ServerCertificate.Certificate),
	}
	for i, certData := range opts.ServerCertificate.Certificate {
		msg.Certificates[i].CertData = certData // those slices are not retained beyond this func
	}
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope
	return handshake.Message{
		MsgType: handshake.MsgTypeCertificate,
		Body:    messageBody,
	}
}

func generateServerCertificateVerify(opts *options.TransportOptions, hctx *handshakeContext) (handshake.Message, error) {
	msg := handshake.MsgCertificateVerify{
		SignatureScheme: handshake.SignatureAlgorithm_RSA_PSS_RSAE_SHA256,
	}

	// [rfc8446:4.4.3] - certificate verification
	var certVerifyTranscriptHashStorage [constants.MaxHashLength]byte
	certVerifyTranscriptHash := hctx.transcriptHasher.Sum(certVerifyTranscriptHashStorage[:0])

	var sigMessageHashStorage [constants.MaxHashLength]byte
	sigMessageHash := signature.CalculateCoveredContentHash(sha256.New(), certVerifyTranscriptHash, sigMessageHashStorage[:0])

	privateRsa := opts.ServerCertificate.PrivateKey.(*rsa.PrivateKey)
	sig, err := signature.CreateSignature_RSA_PSS_RSAE_SHA256(opts.Rnd, privateRsa, sigMessageHash)
	if err != nil {
		log.Printf("create signature error: %v", err)
		return handshake.Message{}, dtlserrors.ErrCertificateVerifyMessageSignature
	}
	msg.Signature = sig
	messageBody := msg.Write(nil) // TODO - reuse message bodies in a rope

	return handshake.Message{
		MsgType: handshake.MsgTypeCertificateVerify,
		Body:    messageBody,
	}, nil
}
