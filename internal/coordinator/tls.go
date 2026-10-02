package coordinator

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
)

// NewWithCA optionally adds an operator-configured CA bundle to the system
// roots for this coordinator only. HTTPS and hostname verification remain
// required; provider transports never inherit these added roots.
func NewWithCA(origin, credential, path string) (*Client, error) {
	client := New(origin, credential)
	if path == "" {
		return client, nil
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" {
		return nil, errors.New("coordinator CA requires HTTPS")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("could not open coordinator CA bundle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("coordinator CA bundle must be a regular file")
	}
	pem, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(pem) > 1<<20 {
		return nil, errors.New("invalid coordinator CA bundle")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("coordinator CA bundle contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client.HTTP.Transport = transport
	return client, nil
}
