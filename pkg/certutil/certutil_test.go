package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed cert+key PEM pair for testing.
func generateSelfSignedCert(cn string) (certPEM []byte, keyPEM []byte, cert *x509.Certificate, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, cert, nil
}

func writeCertFiles(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReadCertFiles_Valid(t *testing.T) {
	certPEM, keyPEM, expectedCert, err := generateSelfSignedCert("test.example.com")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeCertFiles(t, dir, certPEM, keyPEM)

	gotCertPEM, gotKeyPEM, gotCert, err := ReadCertFiles(dir)
	if err != nil {
		t.Fatalf("ReadCertFiles failed: %v", err)
	}

	if string(gotCertPEM) != string(certPEM) {
		t.Error("certPEM mismatch")
	}
	if string(gotKeyPEM) != string(keyPEM) {
		t.Error("keyPEM mismatch")
	}
	if gotCert.Subject.CommonName != expectedCert.Subject.CommonName {
		t.Errorf("CN mismatch: got %q, want %q", gotCert.Subject.CommonName, expectedCert.Subject.CommonName)
	}
}

func TestReadCertFiles_MissingCert(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tls.key"), []byte("key"), 0600)

	_, _, _, err := ReadCertFiles(dir)
	if err == nil {
		t.Fatal("expected error for missing tls.crt")
	}
}

func TestReadCertFiles_MissingKey(t *testing.T) {
	certPEM, _, _, err := generateSelfSignedCert("test.example.com")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0600)

	_, _, _, err = ReadCertFiles(dir)
	if err == nil {
		t.Fatal("expected error for missing tls.key")
	}
}

func TestReadCertFiles_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("not a pem"), 0600)
	os.WriteFile(filepath.Join(dir, "tls.key"), []byte("not a pem"), 0600)

	_, _, _, err := ReadCertFiles(dir)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestReadCertFiles_CertKeyMismatch(t *testing.T) {
	certPEM, _, _, err := generateSelfSignedCert("cert1.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM, _, err := generateSelfSignedCert("cert2.example.com")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeCertFiles(t, dir, certPEM, keyPEM)

	_, _, _, err = ReadCertFiles(dir)
	if err == nil {
		t.Fatal("expected error for cert/key mismatch")
	}
}

func TestReadCertFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	_, _, _, err := ReadCertFiles(dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}


