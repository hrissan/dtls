// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/transport/stats"
)

// TODO - set limits in bytes of memory, let implementation calculate
// internal limits to stay within memory limit

type Options struct {
	RoleServer bool
	Rnd        dtlsrand.Rand
	Stats      stats.Stats

	Preallocate bool // most data structures will be allocated immediately

	// socket delays are not used by DTLS core, they are here for convenience
	SocketReadErrorDelay  time.Duration
	SocketWriteErrorDelay time.Duration

	CookieValidDuration    time.Duration
	MaxHelloRetryQueueSize int
	MaxHandshakes          int // TODO - implement actual limit
	MaxConnections         int

	// Not fully implemented for now, used only during record parsing.
	// We use fixed size connection ID, so we can parse ciphertext records easily [rfc9147:9.1]
	CIDLength int

	// We have to support receiving them, so we also implemented sending them
	Use8BitSeq bool

	// TODO - set priority
	TLS_AES_128_GCM_SHA256       bool
	TLS_AES_256_GCM_SHA384       bool
	TLS_CHACHA20_POLY1305_SHA256 bool

	ServerCertificate tls.Certificate // some shortcut

	// application-layer protocol negotiation
	ALPN                   [][]byte
	ALPNContinueOnMismatch bool

	// Must be set to enable early data.
	ServerDisableHRR    bool
	PSKClientIdentities [][]byte
	// On client, called for each one of PSKClientIdentities set to build pre_shared_key extension.
	// Must append secret to scratch and return it.
	// On server, called for each one of identity sent in pre_shared_key extension.
	// Must append secret to scratch and return it, or return nil.
	PSKAppendSecret func(clientIdentity []byte, scratch []byte) []byte
}

func DefaultTransportOptions(roleServer bool, rnd dtlsrand.Rand, stats stats.Stats) *Options {
	return &Options{
		RoleServer:                   roleServer,
		Rnd:                          rnd,
		Stats:                        stats,
		Preallocate:                  true,
		SocketReadErrorDelay:         50 * time.Millisecond,
		SocketWriteErrorDelay:        5 * time.Millisecond,
		CookieValidDuration:          120 * time.Second, // larger value for debug
		MaxHelloRetryQueueSize:       10_000,
		MaxHandshakes:                1000,
		MaxConnections:               100_000,
		CIDLength:                    0,
		Use8BitSeq:                   false,
		TLS_AES_128_GCM_SHA256:       true,
		TLS_AES_256_GCM_SHA384:       false,
		TLS_CHACHA20_POLY1305_SHA256: false,
	}
}

func (opts *Options) LoadServerCertificate(certificatePath string, privateKeyPEMPath string) error {
	// TODO - this is the only dependency on "crypto/tls", if this stays, we might want to write this code manually
	cert, err := tls.LoadX509KeyPair(certificatePath, privateKeyPEMPath)
	if err != nil {
		return fmt.Errorf("error loading x509 key pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("loaded x509 pem file contains no certificates")
	}
	if len(cert.Certificate) > constants.MaxCertificateChainLength {
		return fmt.Errorf("loaded x509 pem file contains too many (%d) certificates, only %d are supported", len(cert.Certificate), constants.MaxCertificateChainLength)
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return fmt.Errorf("error parsing leaf x509 certificate: %w", err)
	}
	opts.ServerCertificate = cert
	return nil
}

// TODO - actually call Validate(), and prevent change of options on the fly
func (opts *Options) Validate() error {
	if opts.RoleServer {
		if len(opts.ServerCertificate.Certificate) == 0 {
			return fmt.Errorf("tls server requires an x509 certificate and private key to operate")
		}
		// we will not repeat checks in LoadServerCertificate (tls.LoadX509KeyPair)
	}
	if opts.MaxHelloRetryQueueSize < 1 {
		return fmt.Errorf("MaxHelloRetryQueueSize (%d) should be at least 1", opts.MaxHelloRetryQueueSize)
	}
	if opts.CookieValidDuration < time.Second {
		return fmt.Errorf("CookieValidDuration (%v) should be at least %v", opts.CookieValidDuration, time.Second)
	}
	return nil
}

func (opts *Options) FindALPN(protocols [][]byte) (int, []byte) {
	for _, p := range protocols {
		for i, n := range opts.ALPN {
			if string(p) == string(n) {
				return i, n
			}
		}
	}
	return -1, nil
}
