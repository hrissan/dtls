package format

import "errors"

type KeyShareSet struct {
	X25519PublicKeySet    bool
	X25519PublicKey       [32]byte
	SECP256R1PublicKeySet bool
	SECP256R1PublicKey    [64]byte
}

var ErrKeyShareX25519PublicKeyWrongFormat = errors.New("x25519 public key has wrong format")
var ErrKeyShareSECP256R1PublicKeyWrongFormat = errors.New("secp256r1 public key has wrong format")

func (msg *KeyShareSet) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var keyShareType uint16
		if offset, keyShareType, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		var keyShareBody []byte
		if offset, keyShareBody, err = ParserReadUint16Length(body, offset); err != nil {
			return err
		}
		switch keyShareType { // skip unknown
		case 0x001D:
			if len(keyShareBody) != 32 {
				return ErrKeyShareX25519PublicKeyWrongFormat
			}
			msg.X25519PublicKeySet = true
			copy(msg.X25519PublicKey[:], keyShareBody)
		case 0x0017:
			if len(keyShareBody) != 65 || keyShareBody[0] != 4 {
				return ErrKeyShareSECP256R1PublicKeyWrongFormat
			}
			msg.SECP256R1PublicKeySet = true
			copy(msg.SECP256R1PublicKey[:], keyShareBody[1:])
		}
	}
	return nil
}

func (msg *KeyShareSet) Parse(body []byte) (err error) {
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
