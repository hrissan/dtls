package options

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport/stats"
)

type TransportOptions struct {
	RoleServer bool
	Rnd        dtlsrand.Rand
	Stats      stats.Stats

	Preallocate bool // most data structures will be allocated immediately

	SocketReadErrorDelay   time.Duration
	SocketWriteErrorDelay  time.Duration
	CookieValidDuration    time.Duration
	MaxHelloRetryQueueSize int
	MaxConnections         int
	CIDLength              int // We use fixed size connection ID, so we can parse ciphertext records easily [rfc9147:9.1]

	ServerCertificate tls.Certificate // some shortcut
}

func DefaultTransportOptions(roleServer bool, rnd dtlsrand.Rand, stats stats.Stats) *TransportOptions {
	return &TransportOptions{
		RoleServer:             roleServer,
		Rnd:                    rnd,
		Stats:                  stats,
		Preallocate:            true,
		SocketReadErrorDelay:   50 * time.Millisecond,
		SocketWriteErrorDelay:  5 * time.Millisecond,
		CookieValidDuration:    120 * time.Second, // larger value for debug
		MaxHelloRetryQueueSize: 10_000,
		MaxConnections:         100_000,
		CIDLength:              0,
	}
}

func (opts *TransportOptions) LoadServerCertificate(certificatePath string, privateKeyPEMPath string) error {
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
func (opts *TransportOptions) Validate() error {
	if opts.RoleServer {
		if len(opts.ServerCertificate.Certificate) == 0 {
			return fmt.Errorf("tls server requires an x509 certificate and private key to operate")
		}
		// we will not repeat checks in LoadServerCertificate (tls.LoadX509KeyPair)
	}
	if opts.MaxHelloRetryQueueSize < 1 {
		return fmt.Errorf("MaxHelloRetryQueueSize (%d) should be > 0", opts.MaxHelloRetryQueueSize)
	}
	if opts.CookieValidDuration < time.Second {
		return fmt.Errorf("CookieValidDuration (%v) should be at least %v", opts.CookieValidDuration, time.Second)
	}
	return nil
}
