package unifi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestNewUniFi_MissingUsername(t *testing.T) {
	os.Unsetenv(envUsername)
	os.Unsetenv(envPassword)

	_, err := newUniFi("https://unifi.example.com", false)
	if err == nil {
		t.Fatal("expected error when username env var is missing")
	}
}

func TestNewUniFi_MissingPassword(t *testing.T) {
	t.Setenv(envUsername, "admin")
	os.Unsetenv(envPassword)

	_, err := newUniFi("https://unifi.example.com", false)
	if err == nil {
		t.Fatal("expected error when password env var is missing")
	}
}

func TestNewUniFi_Valid(t *testing.T) {
	t.Setenv(envUsername, "admin")
	t.Setenv(envPassword, "secret")

	target, err := newUniFi("https://unifi.example.com", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, ok := target.(*UniFi)
	if !ok {
		t.Fatal("expected *UniFi type")
	}
	if u.username != "admin" {
		t.Errorf("username = %q, want %q", u.username, "admin")
	}
	if u.password != "secret" {
		t.Errorf("password = %q, want %q", u.password, "secret")
	}
	if !u.insecure {
		t.Error("expected insecure=true")
	}
}

func TestCertFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	fp := certFingerprint(cert)

	// Should be colon-separated uppercase hex, 20 bytes = 59 chars (20*3 - 1)
	if len(fp) != 59 {
		t.Errorf("fingerprint length = %d, want 59, got %q", len(fp), fp)
	}

	// Same cert should produce same fingerprint
	if fp2 := certFingerprint(cert); fp != fp2 {
		t.Error("fingerprint is not deterministic")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestClose(t *testing.T) {
	u := &UniFi{}
	if err := u.Close(); err != nil {
		t.Errorf("Close should not error, got: %v", err)
	}
}
