package handshake

import (
	"encoding/binary"

	"github.com/hrissan/dtls/format"
)

// TODO - use rope for all variable memory chunks
// for now after parsing those slices point to datagram, so must be copied or discarded before next datagram is read
type MsgCertificateVerify struct {
	SignatureScheme uint16
	Signature       []byte
}

func (msg *MsgCertificateVerify) MessageKind() string { return "handshake" }
func (msg *MsgCertificateVerify) MessageName() string { return "CertificateVerify" }

func (msg *MsgCertificateVerify) Parse(body []byte) (err error) {
	offset := 0
	if offset, msg.SignatureScheme, err = format.ParserReadUint16(body, offset); err != nil {
		return err
	}
	if offset, msg.Signature, err = format.ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	return format.ParserReadFinish(body, offset)
}

func (msg *MsgCertificateVerify) Write(body []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, msg.SignatureScheme)
	body, mark := format.MarkUint16Offset(body)
	body = append(body, msg.Signature...)
	format.FillUint16Offset(body, mark)
	return body
}
