// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

// after parsing, those slices point to datagram, so must be copied or
// discarded before next datagram is read
type CertificateEntry struct {
	CertData        []byte
	ExtenstionsData []byte // we do not write extensions, and skip during read
}
