package format

type SupportedVersionsSet struct {
	DTLS_13 bool
}

func (msg *SupportedVersionsSet) parseInside(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var version uint16
		if offset, version, err = ParserUint16(body, offset); err != nil {
			return err
		}
		switch version { // skip unknown
		case 0xFEFC:
			msg.DTLS_13 = true
		}
	}
	return nil
}

func (msg *SupportedVersionsSet) Parse(body []byte) (err error) {
	offset := 0
	var insideBody []byte
	if offset, insideBody, err = ParserByteLength(body, offset); err != nil {
		return err
	}
	if err := msg.parseInside(insideBody); err != nil {
		return err
	}
	return ParserFinish(body, offset)
}
