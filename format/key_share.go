package format

import (
	"encoding/binary"
	"errors"
)

type KeyShareSet struct {
	X25519PublicKeySet    bool
	X25519PublicKey       [32]byte
	SECP256R1PublicKeySet bool
	SECP256R1PublicKey    [64]byte

	// Be careful to set this extension only when strictly needed, conditions are specified in [rfc8446:4.2.8]
	// otherwise client will abort connection
	KeyShareHRRSelectedGroup uint16
}

var ErrKeyShareX25519PublicKeyWrongFormat = errors.New("x25519 public key has wrong format")
var ErrKeyShareSECP256R1PublicKeyWrongFormat = errors.New("secp256r1 public key has wrong format")
var ErrKeyShareHRRWrongFormat = errors.New("HRR key_share must contain single selected group")

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
		case SupportedGroup_X25519:
			if len(keyShareBody) != 32 {
				return ErrKeyShareX25519PublicKeyWrongFormat
			}
			msg.X25519PublicKeySet = true
			copy(msg.X25519PublicKey[:], keyShareBody)
		case SupportedGroup_SECP256R1:
			if len(keyShareBody) != 65 || keyShareBody[0] != 4 {
				return ErrKeyShareSECP256R1PublicKeyWrongFormat
			}
			msg.SECP256R1PublicKeySet = true
			copy(msg.SECP256R1PublicKey[:], keyShareBody[1:])
		}
	}
	return nil
}

func (msg *KeyShareSet) Parse(body []byte, isHelloRetryRequest bool) (err error) {
	offset := 0
	if isHelloRetryRequest {
		if offset, msg.KeyShareHRRSelectedGroup, err = ParserReadUint16(body, offset); err != nil {
			return err
		}
		return ParserReadFinish(body, offset)
	}
	var insideBody []byte
	if offset, insideBody, err = ParserReadUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return ParserReadFinish(body, offset)
}

func (msg *KeyShareSet) Write(body []byte, isServerHello bool, isHelloRetryRequest bool) []byte {
	if isHelloRetryRequest {
		body = binary.BigEndian.AppendUint16(body, msg.KeyShareHRRSelectedGroup)
		return body
	}
	var mark int
	if isServerHello {
		if msg.X25519PublicKeySet {
			body = binary.BigEndian.AppendUint16(body, SupportedGroup_X25519)
			body, mark = MarkUin16Offset(body)
			body = append(body, msg.X25519PublicKey[:]...)
			FillUin16Offset(body, mark)
			return body
		}
		if msg.SECP256R1PublicKeySet {
			body = binary.BigEndian.AppendUint16(body, SupportedGroup_SECP256R1)
			body, mark = MarkUin16Offset(body)
			body = append(body, 4)
			body = append(body, msg.SECP256R1PublicKey[:]...)
			FillUin16Offset(body, mark)
			return body
		}
		panic("server hello must contain single selected key_share")
	}
	body, externalMark := MarkUin16Offset(body)
	if msg.X25519PublicKeySet {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_X25519)
		body, mark = MarkUin16Offset(body)
		body = append(body, msg.X25519PublicKey[:]...)
		FillUin16Offset(body, mark)
	}
	if msg.SECP256R1PublicKeySet {
		body = binary.BigEndian.AppendUint16(body, SupportedGroup_SECP256R1)
		body, mark = MarkUin16Offset(body)
		body = append(body, 4)
		body = append(body, msg.SECP256R1PublicKey[:]...)
		FillUin16Offset(body, mark)
	}
	FillUin16Offset(body, externalMark)
	return body
}
