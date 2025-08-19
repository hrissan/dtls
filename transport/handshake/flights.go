package statemachine

import "github.com/hrissan/tinydtls/format"

const (
	// zero is reserved as a flag for "flight not set"
	MessagesFlightClientHello1               = 1
	MessagesFlightServerHRR                  = 2
	MessagesFlightClientHello2               = 3
	MessagesFlightServerHello_Finished       = 4 // ServerHello, EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished
	MessagesFlightClientCertificate_Finished = 5 // Certificate, CertificateVerify, Finished
)

// returns 0 for messages not related to handshake flights
// we need this function, because we want to clear acks for previous flight when we receive
// fragment of the message from the next flight. If we wait until we reassemble complete message,
// we'd not be able to clear acks for previous messages.
func HandshakeTypeToFlight(handshakeType byte, roleServer bool) byte {
	switch handshakeType {
	// case format.HandshakeTypeClientHello: - they are processed by separate state machine
	// case format.HandshakeTypeServerHello: - they are processed by separate state machine
	case format.HandshakeTypeEncryptedExtensions:
		return MessagesFlightServerHello_Finished
	case format.HandshakeTypeCertificate:
	case format.HandshakeTypeCertificateRequest:
	case format.HandshakeTypeCertificateVerify:
	case format.HandshakeTypeFinished:
		if roleServer {
			return MessagesFlightServerHello_Finished
		}
		return MessagesFlightClientCertificate_Finished
	}
	return 0
}
