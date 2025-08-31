// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package handshake

// after parsing, slices inside point to datagram, so must not be retained
type CertificateEntry struct {
	CertData        []byte
	ExtenstionsData []byte // we do not write extensions, and skip during read
}
