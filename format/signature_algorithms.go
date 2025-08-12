package format

import "encoding/binary"

const (
	SignatureAlgorithm_ECDSA_SECP256r1_SHA256 = 0x0403
	SignatureAlgorithm_ECDSA_SECP384r1_SHA384 = 0x0503
	SignatureAlgorithm_ECDSA_SECP512r1_SHA512 = 0x0603
	SignatureAlgorithm_ECDSA_SHA1             = 0x0203
	SignatureAlgorithm_ED25519                = 0x0807
	SignatureAlgorithm_ED448                  = 0x0808
)

type SignatureAlgorithmsSet struct {
	// We do not want to support with RSA, due to certificate size
	ECDSA_SECP256r1_SHA256 bool
	ECDSA_SECP384r1_SHA384 bool
	ECDSA_SECP512r1_SHA512 bool
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
		case SignatureAlgorithm_ECDSA_SECP256r1_SHA256:
			msg.ECDSA_SECP256r1_SHA256 = true
		case SignatureAlgorithm_ECDSA_SECP384r1_SHA384:
			msg.ECDSA_SECP384r1_SHA384 = true
		case SignatureAlgorithm_ECDSA_SECP512r1_SHA512:
			msg.ECDSA_SECP512r1_SHA512 = true
		case SignatureAlgorithm_ECDSA_SHA1:
			msg.ECDSA_SHA1 = true
		case SignatureAlgorithm_ED25519:
			msg.ED25519 = true
		case SignatureAlgorithm_ED448:
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
	body, mark := MarkUint16Offset(body)
	if msg.ECDSA_SECP256r1_SHA256 {
		body = binary.BigEndian.AppendUint16(body, SignatureAlgorithm_ECDSA_SECP256r1_SHA256)
	}
	if msg.ECDSA_SECP384r1_SHA384 {
		body = binary.BigEndian.AppendUint16(body, SignatureAlgorithm_ECDSA_SECP384r1_SHA384)
	}
	if msg.ECDSA_SECP512r1_SHA512 {
		body = binary.BigEndian.AppendUint16(body, SignatureAlgorithm_ECDSA_SECP512r1_SHA512)
	}
	if msg.ECDSA_SHA1 {
		body = binary.BigEndian.AppendUint16(body, SignatureAlgorithm_ECDSA_SHA1)
	}
	if msg.ED25519 {
		body = binary.BigEndian.AppendUint16(body, SignatureAlgorithm_ED25519)
	}
	if msg.ED448 {
		body = binary.BigEndian.AppendUint16(body, SignatureAlgorithm_ED448)
	}
	FillUint16Offset(body, mark)
	return body
}
