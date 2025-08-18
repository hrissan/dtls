package format

import "encoding/binary"

// TODO - use rope for all variable memory chunks
// for now after parsing those slices point to datagram, so must be copied or discarded before next datagram is read
type MessageCertificateVerify struct {
	SignatureScheme uint16
	Signature       []byte
}

func (msg *MessageCertificateVerify) MessageKind() string { return "handshake" }
func (msg *MessageCertificateVerify) MessageName() string { return "CertificateVerify" }

func (msg *MessageCertificateVerify) Parse(body []byte) (err error) {
	offset := 0
	if offset, msg.SignatureScheme, err = ParserReadUint16(body, offset); err != nil {
		return err
	}
	if offset, msg.Signature, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *MessageCertificateVerify) Write(body []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, msg.SignatureScheme)
	body, mark := MarkUint16Offset(body)
	body = append(body, msg.Signature...)
	FillUint16Offset(body, mark)
	return body
}
