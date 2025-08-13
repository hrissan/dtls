package format

type MessageCertificate struct {
	// ProtocolVersion is checked but not stored
	RequestContextLength int
	RequestContext       [256]byte // always enough

	Certificates []CertificateEntry
}

func (msg *MessageCertificate) MessageKind() string { return "handshake" }
func (msg *MessageCertificate) MessageName() string { return "certificate" }

func (msg *MessageCertificate) parseCertificates(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var entry CertificateEntry
		if offset, entry.CertData, err = ParserReadUint24Length(body, offset); err != nil {
			return err
		}
		if offset, entry.ExtenstionsData, err = ParserReadUint16Length(body, offset); err != nil {
			return err
		}
		msg.Certificates = append(msg.Certificates, entry)
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
	panic("TODO")
	return body
}
