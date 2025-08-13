package format

import "crypto/x509"

// TODO - use rope for all variable memory chunks
// for now after parsing those slices point to datagram, so must be copied or discarded before next datagram is read
type CertificateEntry struct {
	// CertData        []byte
	// ExtenstionsData []byte - we do not write extensions, and skip during read
	// TODO - after we have ropes, do not load certificates until start of checking
	Cert *x509.Certificate
}
