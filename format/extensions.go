package format

type ExtensionsSet struct {
	SupportedVersions   SupportedVersionsSet
	SupportedGroups     SupportedGroupsSet
	SignatureAlgorithms SignatureAlgorithmsSet
	KeyShare            KeyShareSet
}

func (msg *ExtensionsSet) Parse(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var extensionType uint16
		if offset, extensionType, err = ParserUint16(body, offset); err != nil {
			return err
		}
		var extensionBody []byte
		if offset, extensionBody, err = ParserUint16Length(body, offset); err != nil {
			return err
		}
		switch extensionType { // skip unknown/not needed
		case 0x000a: // Supported Groups
			if err := msg.SupportedGroups.Parse(extensionBody); err != nil {
				return err
			}
		case 0x000d: // Signature Algorithms
			if err := msg.SignatureAlgorithms.Parse(extensionBody); err != nil {
				return err
			}
		case 0x002a: // Early Data
		// TODO
		case 0x002b: // Supported Versions
			if err := msg.SupportedVersions.Parse(extensionBody); err != nil {
				return err
			}
		case 0x002c: // Cookie
		// TODO
		case 0x0033: // Key Share
			if err := msg.KeyShare.Parse(extensionBody); err != nil {
				return err
			}
		}
	}
	return nil
}
