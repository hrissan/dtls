package dtlserrors

import (
	"fmt"
)

// we do not allocation on error returning path,
// so all errors are completely static

type Error struct {
	fatal bool
	code  int
	text  string
}

func (e *Error) Error() string {
	if e.fatal {
		return fmt.Sprintf("tinydtls (fatal): %d %s", e.code, e.text)
	}
	return fmt.Sprintf("tinydtls (warning): %d %s", e.code, e.text)
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
		fatal: true,
		code:  code,
		text:  text,
	}
}

var WarnServerHelloFragmented = NewWarning(-398, "fragmented ServerHello message not supported")
var WarnClientHelloFragmented = NewWarning(-399, "fragmented ClientHello message not supported")
var WarnNewSessionTicketFragmented = NewWarning(-400, "fragmented NewSessionTicket message not supported, waiting for retransmission")
var WarnKeyUpdateFragmented = NewWarning(-401, "fragmented KeyUpdate message not supported, waiting for retransmission")
var WarnUnknownInnerPlaintextRecordType = NewWarning(-402, "unknown inner plaintext record type")
var WarnAckEpochOverflow = NewWarning(-403, "ack record epoch overflows 2^16")
var WarnPlaintextRecordParsing = NewWarning(-405, "plaintext record header failed to parse")
var WarnCiphertextRecordParsing = NewWarning(-406, "ciphertext record header failed to parse")
var WarnCiphertextNoConnection = NewWarning(-407, "received ciphertext without connection")
var WarnFailedToDeprotectRecord = NewWarning(-408, "failed to deprotect encrypted record")
var WarnPlaintextHandshakeMessageHeaderParsing = NewWarning(-409, "plaintext handshake message header failed to parse")
var WarnPlaintextClientHelloParsing = NewWarning(-410, "plaintext ClientHello message failed to parse")
var WarnPlaintextServerHelloParsing = NewWarning(-411, "plaintext ServerHello message failed to parse")
var WarnHandshakeMessageMustBeEncrypted = NewWarning(-412, "plaintext handshake messages other than ClientHello, ServerHello must be encrypted")
var WarnUnknownRecordType = NewWarning(-413, "record header does not match plaintext or ciphertext format")

var ErrUpdatingKeysWouldOverflowEpoch = NewFatal(-500, "updating keys would overflow epoch")
var ErrPostHandshakeMessageDuringHandshake = NewWarning(-501, "post-handshake message during handshake")
var ErrEncryptedHandshakeMessageHeaderParsing = NewWarning(-502, "encrypted handshake message header failed to parse")
var ErrServerHelloMustNotBeEncrypted = NewWarning(-503, "ServerHello must not be encrypted")
var ErrClientHelloMustNotBeEncrypted = NewWarning(-504, "ClientHello must not be encrypted")
var ErrHandshakeMessageFragmentLengthMismatch = NewWarning(-505, "handshake message fragment has different length than received before")
var ErrHandshakeMessageFragmentTypeMismatch = NewWarning(-506, "handshake message fragment has different type than received before")
var ErrExtensionsMessageParsing = NewWarning(-507, "Extensions handshake message failed to parse")
var ErrCertificateMessageParsing = NewWarning(-508, "Certificate handshake message failed to parse")
var ErrCertificateVerifyMessageParsing = NewWarning(-509, "CertificateVerify handshake message failed to parse")
var ErrFinishedMessageParsing = NewWarning(-510, "Finished handshake message failed to parse")

var ErrCertificateChainEmpty = NewWarning(-511, "certificate chain is empty")
var ErrCertificateLoadError = NewWarning(-512, "certificate load error")
var ErrCertificateAlgorithmUnsupported = NewWarning(-513, "certificate algorihtm unsupported")
var ErrCertificateSignatureInvalid = NewWarning(-514, "certificate signature invalid")
var ErrFinishedMessageVerificationFailed = NewWarning(-515, "finished message verification failed")

var ErrEncryptedAckMessageHeaderParsing = NewWarning(-516, "encrypted ack message header failed to parsed")
