package certutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func validateKeyPair(certPEM, keyPEM []byte) error {
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("cert/key mismatch: %w", err)
	}
	return nil
}

func ReadCertFiles(dir string) (certPEM []byte, keyPEM []byte, cert *x509.Certificate, err error) {
	certPEM, err = os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading tls.crt: %w", err)
	}

	keyPEM, err = os.ReadFile(filepath.Join(dir, "tls.key"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading tls.key: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, nil, fmt.Errorf("failed to decode PEM block from tls.crt")
	}

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing certificate: %w", err)
	}

	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return nil, nil, nil, err
	}

	return certPEM, keyPEM, cert, nil
}


