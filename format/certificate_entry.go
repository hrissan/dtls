package format

// TODO - use rope for all variable memory chunks
// for now after parsing those slices point to datagram, so must be copied or discarded before next datagram is read
type CertificateEntry struct {
	CertData        []byte
	ExtenstionsData []byte
}
