package target

import (
	"context"
	"crypto/x509"
	"fmt"
)

type Target interface {
	// EnsureCert ensures the given certificate is imported and active on the remote system.
	// Returns the certificate currently active on the remote system.
	EnsureCert(ctx context.Context, certPEM []byte, keyPEM []byte, cert *x509.Certificate, certName string) (*x509.Certificate, error)
	Close() error
}

type Factory func(url string, insecure bool) (Target, error)

var registry = map[string]Factory{}

func Register(name string, factory Factory) {
	registry[name] = factory
}

func Create(typeName string, url string, insecure bool) (Target, error) {
	factory, ok := registry[typeName]
	if !ok {
		return nil, fmt.Errorf("unknown target type: %q", typeName)
	}
	return factory(url, insecure)
}

