package format

type CipherSuitesSet struct {
	// each known CipherSuite is represented by a bool, all unknown are skipped
	HasCypherSuite_TLS_AES_128_GCM_SHA256       bool
	HasCypherSuite_TLS_AES_256_GCM_SHA384       bool
	HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 bool
	HasCypherSuite_TLS_AES_128_CCM_SHA256       bool
	HasCypherSuite_TLS_AES_128_CCM_8_SHA256     bool
}

func (msg *CipherSuitesSet) Parse(body []byte) (err error) {
	offset := 0
	for offset < len(body) {
		var cipherSuite uint16
		if offset, cipherSuite, err = ParserUint16(body, offset); err != nil {
			return err
		}
		switch cipherSuite { // skip unknown
		case 0x1301:
			msg.HasCypherSuite_TLS_AES_128_GCM_SHA256 = true
		case 0x1302:
			msg.HasCypherSuite_TLS_AES_256_GCM_SHA384 = true
		case 0x1303:
			msg.HasCypherSuite_TLS_CHACHA20_POLY1305_SHA256 = true
		case 0x1304:
			msg.HasCypherSuite_TLS_AES_128_CCM_SHA256 = true
		case 0x1305:
			msg.HasCypherSuite_TLS_AES_128_CCM_8_SHA256 = true
		}
	}
	return nil
}
