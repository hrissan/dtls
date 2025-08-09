package format

type SignatureAlgorithmsSet struct {
	// We do not want to support with RSA, due to certificate size
	ECDSA_SECP512r1_SHA512 bool
	ECDSA_SECP384r1_SHA384 bool
	ECDSA_SECP256r1_SHA256 bool
	ECDSA_SHA1             bool
	ED25519                bool
	ED448                  bool
}

func (msg *SignatureAlgorithmsSet) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var version uint16
		if offset, version, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		switch version { // skip unknown
		case 0x0603:
			msg.ECDSA_SECP512r1_SHA512 = true
		case 0x0503:
			msg.ECDSA_SECP384r1_SHA384 = true
		case 0x0403:
			msg.ECDSA_SECP256r1_SHA256 = true
		case 0x0203:
			msg.ECDSA_SHA1 = true
		case 0x0807:
			msg.ED25519 = true
		case 0x0808:
			msg.ED448 = true
		}
	}
	return nil
}

func (msg *SignatureAlgorithmsSet) Parse(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *SignatureAlgorithmsSet) Write(body []byte) []byte {
	// TODO
	return body
}
