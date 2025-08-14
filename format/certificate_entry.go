package format

// TODO - use rope for all variable memory chunks
type CertificateEntry struct {
	CertData        []byte
	ExtenstionsData []byte // we do not write extensions, and skip during read
}
