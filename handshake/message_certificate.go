package handshake

import (
	"errors"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
)

var ErrCertificateChainTooLong = errors.New("certificate chain is too long")

type MsgCertificate struct {
	// ProtocolVersion is checked but not stored
	RequestContextLength int
	RequestContext       [256]byte // always enough

	CertificatesLength int
	Certificates       [constants.MaxCertificateChainLength]CertificateEntry
}

func (msg *MsgCertificate) MessageKind() string { return "handshake" }
func (msg *MsgCertificate) MessageName() string { return "Certificate" }

func (msg *MsgCertificate) parseCertificates(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		if msg.CertificatesLength >= len(msg.Certificates) {
			return ErrCertificateChainTooLong
		}
		var certData []byte
		if offset, certData, err = format.ParserReadUint24Length(body, offset); err != nil {
			return err
		}
		var externsionData []byte
		if offset, externsionData, err = format.ParserReadUint16Length(body, offset); err != nil {
			return err
		}
		// TODO - use rope here
		msg.Certificates[msg.CertificatesLength].CertData = append([]byte(nil), certData...)
		msg.Certificates[msg.CertificatesLength].ExtenstionsData = append([]byte(nil), externsionData...)
		msg.CertificatesLength++
	}
	return nil
}

func (msg *MsgCertificate) Parse(body []byte) (err error) {
	offset := 0
	var requestContextBody []byte
	if offset, requestContextBody, err = format.ParserReadByteLength(body, offset); err != nil {
		return err
	}
	msg.RequestContextLength = len(requestContextBody)
	copy(msg.RequestContext[:], requestContextBody)
	var certificatesBody []byte
	if offset, certificatesBody, err = format.ParserReadUint24Length(body, offset); err != nil {
		return err
	}
	if err = msg.parseCertificates(certificatesBody); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *MsgCertificate) Write(body []byte) []byte {
	body, mark := format.MarkByteOffset(body)
	body = append(body, msg.RequestContext[:msg.RequestContextLength]...)
	format.FillByteOffset(body, mark)
	body, mark = format.MarkUint24Offset(body)
	for _, c := range msg.Certificates[:msg.CertificatesLength] {
		var insideMark int
		body, insideMark = format.MarkUint24Offset(body)
		body = append(body, c.CertData...)
		format.FillUint24Offset(body, insideMark)
		body, insideMark = format.MarkUint16Offset(body)
		body = append(body, c.ExtenstionsData...)
		format.FillUint16Offset(body, insideMark)
	}
	format.FillUint24Offset(body, mark)
	return body
}
