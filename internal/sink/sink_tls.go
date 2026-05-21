package sink

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// buildTLSConfig builds a *tls.Config for a stream sink dialing over TLS
// (syslog network=tls, mqtt tls:// broker). Default verifies against the
// system roots; CACertFile pins a custom CA; TLSInsecure disables
// verification (lab use only); TLSServerName overrides the SNI / verify
// name. A nil return with nil error means "use the dialer default".
func buildTLSConfig(ch config.Channel) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: ch.TLSInsecure,
		ServerName:         ch.TLSServerName,
	}
	if ch.CACertFile != "" {
		pem, err := os.ReadFile(ch.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert_file %s: no certificates found", ch.CACertFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// hostOnly strips the :port from a host:port address (for SNI defaults).
func hostOnly(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
