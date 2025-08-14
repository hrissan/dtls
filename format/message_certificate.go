package format

import (
	"errors"

	"github.com/hrissan/tinydtls/constants"
)

var ErrCertificateChainTooLong = errors.New("certificate chain is too long")

type MessageCertificate struct {
	// ProtocolVersion is checked but not stored
	RequestContextLength int
	RequestContext       [256]byte // always enough

	CertificatesLength int
	Certificates       [constants.MaxCertificateChainLength]CertificateEntry
}

func (msg *MessageCertificate) MessageKind() string { return "handshake" }
func (msg *MessageCertificate) MessageName() string { return "certificate" }

func (msg *MessageCertificate) parseCertificates(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		if msg.CertificatesLength >= len(msg.Certificates) {
			return ErrCertificateChainTooLong
		}
		var certData []byte
		if offset, certData, err = ParserReadUint24Length(body, offset); err != nil {
			return err
		}
		var externsionData []byte
		if offset, externsionData, err = ParserReadUint16Length(body, offset); err != nil {
			return err
		}
		// TODO - use rope here
		msg.Certificates[msg.CertificatesLength].CertData = append([]byte(nil), certData...)
		msg.Certificates[msg.CertificatesLength].ExtenstionsData = append([]byte(nil), externsionData...)
		msg.CertificatesLength++
	}
	return nil
}

func (msg *MessageCertificate) Parse(body []byte) (err error) {
	offset := 0
	var requestContextBody []byte
	if offset, requestContextBody, err = ParserReadByteLength(body, offset); err != nil {
		return err
	}
	msg.RequestContextLength = len(requestContextBody)
	copy(msg.RequestContext[:], requestContextBody)
	var certificatesBody []byte
	if offset, certificatesBody, err = ParserReadUint24Length(body, offset); err != nil {
		return err
	}
	if err = msg.parseCertificates(certificatesBody); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *MessageCertificate) Write(body []byte) []byte {
	body, mark := MarkByteOffset(body)
	body = append(body, msg.RequestContext[:msg.RequestContextLength]...)
	FillByteOffset(body, mark)
	body, mark = MarkUint24Offset(body)
	for _, c := range msg.Certificates[:msg.CertificatesLength] {
		var insideMark int
		body, insideMark = MarkUint24Offset(body)
		body = append(body, c.CertData...)
		FillUint24Offset(body, insideMark)
		body, insideMark = MarkUint16Offset(body)
		body = append(body, c.ExtenstionsData...)
		FillUint16Offset(body, insideMark)
	}
	FillUint24Offset(body, mark)
	return body
}
