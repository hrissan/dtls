// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

import (
	"errors"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/format"
)

var ErrCertificateChainTooLong = errors.New("certificate chain is too long")

// after parsing, slices inside point to datagram, so must not be retained
type MsgCertificate struct {
	// ProtocolVersion is checked but not stored
	RequestContext []byte

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
		msg.Certificates[msg.CertificatesLength].CertData = append([]byte{}, certData...)
		msg.Certificates[msg.CertificatesLength].ExtenstionsData = append([]byte{}, externsionData...)
		msg.CertificatesLength++
	}
	return nil
}

func (msg *MsgCertificate) Parse(body []byte) (err error) {
	offset := 0
	if offset, msg.RequestContext, err = format.ParserReadByteLength(body, offset); err != nil {
		return err
	}
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
	body = append(body, msg.RequestContext...)
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
