package format

type SupportedGroupsSet struct {
	X25519    bool
	SECP256R1 bool
	SECP384R1 bool
	SECP521R1 bool
	X448      bool
}

func (msg *SupportedGroupsSet) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var version uint16
		if offset, version, err = ParserUint16(body, offset); err != nil {
			return err
		}
		switch version { // skip unknown
		case 0x001D:
			msg.X25519 = true
		case 0x0017:
			msg.SECP256R1 = true
		case 0x0018:
			msg.SECP384R1 = true
		case 0x0019:
			msg.SECP521R1 = true
		case 0x001E:
			msg.X448 = true
		}
	}
	return nil
}

func (msg *SupportedGroupsSet) Parse(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = ParserUint16Length(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return ParserFinish(body, offset)
}
