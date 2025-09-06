// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlserrors

import (
	"errors"
	"fmt"
)

// we want no allocations on error returning path,
// so all errors are completely static.
// TODO - after they stop changing, assign unique codes)

type Error struct {
	fatal bool
	code  int
	text  string
}

func (e *Error) Fatal() bool {
	return e.fatal
}

func (e *Error) Error() string {
	if e.fatal {
		return fmt.Sprintf("dtls (fatal): %d %s", e.code, e.text)
	}
	return fmt.Sprintf("dtls (warning): %d %s", e.code, e.text)
}

func IsFatal(err error) bool { // we do not use errors package for now
	if err == nil {
		return false
	}
	if e, ok := err.(*Error); ok {
		return e.fatal
	}
	return true // TODO - panic here after we replace all error with dtlserrors.Error
}

func NewFatal(code int, text string) error {
	return &Error{
		fatal: true,
		code:  code,
		text:  text,
	}
}

func NewWarning(code int, text string) error {
	return &Error{
		fatal: false,
		code:  code,
		text:  text,
	}
}

var WarnServerHelloFragmented = NewWarning(-398, "fragmented ServerHello message not supported")
var WarnClientHelloFragmented = NewWarning(-399, "fragmented ClientHello message not supported")
var WarnPostHandshakeMessageFragmented = NewWarning(-400, "fragmented post-handshake message not supported by this implementation, waiting for retransmission")
var WarnAckEpochSeqnumOverflow = NewWarning(-403, "ack record epoch overflows 2^16")
var WarnPlaintextRecordParsing = NewWarning(-405, "plaintext record header failed to parse")
var WarnCiphertextRecordParsing = NewWarning(-406, "ciphertext record header failed to parse")
var WarnCiphertextNoConnection = NewWarning(-407, "received ciphertext without connection")
var WarnFailedToDeprotectRecord = NewWarning(-408, "failed to deprotect encrypted record")
var WarnPlaintextHandshakeMessageHeaderParsing = NewWarning(-409, "plaintext handshake message header failed to parse")
var WarnPlaintextClientHelloParsing = NewWarning(-410, "plaintext ClientHello message failed to parse")
var WarnPlaintextServerHelloParsing = NewWarning(-411, "plaintext ServerHello message failed to parse")
var WarnUnknownRecordType = NewWarning(-413, "record header does not match plaintext or ciphertext format")

var ErrUpdatingKeysWouldOverflowEpoch = NewFatal(-500, "updating keys would overflow epoch")
var ErrEncryptedHandshakeMessageHeaderParsing = NewWarning(-502, "encrypted handshake message header failed to parse")
var ErrServerHelloMustNotBeEncrypted = NewWarning(-503, "ServerHello must not be encrypted")
var ErrClientHelloMustNotBeEncrypted = NewWarning(-504, "ClientHello must not be encrypted")
var ErrHandshakeMessageFragmentLengthMismatch = NewWarning(-505, "handshake message fragment has different length than received before")
var ErrHandshakeMessageFragmentTypeMismatch = NewWarning(-506, "handshake message fragment has different type than received before")
var ErrExtensionsMessageParsing = NewWarning(-507, "Extensions handshake message failed to parse")
var ErrCertificateMessageParsing = NewWarning(-508, "Certificate handshake message failed to parse")
var ErrCertificateVerifyMessageParsing = NewWarning(-509, "CertificateVerify handshake message failed to parse")
var ErrFinishedMessageParsing = NewWarning(-510, "Finished handshake message failed to parse")
var ErrKeyUpdateMessageParsing = NewWarning(-511, "KeyUpdate handshake message failed to parse")

var ErrUnexpectedMessage = NewWarning(-507, "unexpected message")

var ErrCertificateChainEmpty = NewWarning(-512, "certificate chain is empty")
var ErrCertificateLoadError = NewWarning(-513, "certificate load error")
var ErrCertificateAlgorithmUnsupported = NewWarning(-514, "certificate algorihtm unsupported")
var ErrCertificateSignatureInvalid = NewWarning(-515, "certificate signature invalid")
var ErrFinishedMessageVerificationFailed = NewWarning(-516, "finished message verification failed")
var ErrPSKBinderVerificationFailed = NewWarning(-516, "psk binder verification failed")

var ErrEncryptedAckMessageHeaderParsing = NewWarning(-516, "encrypted ack message header failed to parsed")

var ErrReceivedMessageSeqOverflow = NewWarning(-517, "received handshake message sequence limit of 2^16-1 reached, closing connection")
var ErrSendMessageSeqOverflow = NewWarning(-517, "sent handshake message sequence limit of 2^16-1 reached, closing connection")

var ErrSendEpoch0RecordSeqOverflow = NewWarning(-518, "sending plaintext record sequence number reached 2^16-1 (implementation limit), closing connection")
var ErrSendRecordSeqOverflow = NewWarning(-519, "sending ciphertext record sequence number reached limit (peer did not ack our KeyUpdate?), closing connection")
var ErrReceiveRecordSeqOverflow = NewWarning(-520, "receiving ciphertext record sequence number reached limit (peer did not react to our KeyUpdate request?), closing connection")
var ErrReceiveRecordSeqOverflowNextEpoch = NewWarning(-521, "receiving ciphertext record sequence number for a new epoch reached limit, closing connection")

// records format
var ErrAckRecordMustBeEncrypted = NewWarning(-600, "ack record must always be encrypted")
var ErrUnknownInnerPlaintextRecordType = NewWarning(-602, "unknown inner plaintext record type")
var ErrHandshakeRecordEmpty = NewWarning(-603, "handshake record must not be empty")

// encryption
var WarnCannotDecryptInEpoch0 = NewWarning(-300, "cannot decrypt record at epoch 0")
var WarnEpochDoesNotMatch = NewWarning(-300, "received record epoch bitmask does not match current or next epoch")
var WarnCipherTextTooShortForSNDecryption = NewWarning(-300, "ciphertext too short for SN decryption")
var WarnAEADDeprotectionFailed = NewWarning(-300, "ciphertext AEAD decryption failed")
var ErrCipherTextAllZeroPadding = NewFatal(-300, "ciphertext all zero padding") // fatal, because inside deprotected record

// handshake protocol
var WarnHandshakeMessageMustBeEncrypted = NewWarning(-700, "plaintext handshake messages other than ClientHello, ServerHello must be encrypted")

var ErrPostHandshakeMessageDuringHandshake = NewWarning(-701, "post-handshake message during handshake")
var ErrHandshakeMessagePostHandshake = NewWarning(-702, "handshake message received post handshake")
var ErrHandshakeMessageTypeUnknown = NewWarning(-703, "handshake message type unknown")

var ErrEncryptedExtensionsReceivedByServer = NewWarning(-701, "EncryptedExtensions handshake message rsceived by server")
var ErrClientHelloReceivedByClient = NewWarning(-702, "ClientHello handshake message rsceived by client")
var ErrServerHelloReceivedByServer = NewWarning(-703, "ServerHello handshake message rsceived by server")
var ErrClientHelloUnsupportedParams = NewWarning(-704, "ClientHello unsupported params (version, ciphersuite, groups, etc)") // TODO - more granular error

var ErrParamsSupportOnlyDTLS13 = NewWarning(-705, "unsupported version - only DTLSv1.3 supported")
var ErrParamsSupportCiphersuites = NewWarning(-705, "unsupported ciphersuite")
var ErrParamsSupportKeyShare = NewWarning(-705, "unsupported key share - only X25519 supported")
var ErrPskKeyRequiresPskModes = NewWarning(-705, "pre_shared_key requires psk_key_exchange_modes")
var ErrServerHRRMustContainCookie = errors.New("server HelloRetryRequest must contain valid cookie")
var ErrServerHRRMustHaveMsgSeq0 = errors.New("server HelloRetryRequest must have message seq 0")
var ErrServerMustNotSendPSKModes = NewWarning(-705, "server must not send psk_key_exchange_modes")

var ErrALPNNoCompatibleProtocol = NewFatal(-750, "no compatible ALPN protocol")

var ErrClientHelloCookieInvalid = NewWarning(-705, "ClientHello cookie failed validation")
var ErrClientHelloCookieAge = NewWarning(-706, "ClientHello cookie expired")
var ErrServerHelloRetryRequestQueueFull = NewWarning(-707, "Server's HelloRetryRequest queue is full, dropping ClientHello")
var ErrServerHelloNoActiveConnection = NewWarning(-708, "client received ServerHello, but has no active connection to address")

// crypto related
var ErrCertificateVerifyMessageSignature = NewWarning(-800, "failed to sign CertificateVerify handshake message")
