package target

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"
)

type mockTarget struct{}

func (m *mockTarget) EnsureCert(ctx context.Context, certPEM, keyPEM []byte, cert *x509.Certificate, name string) (*x509.Certificate, error) {
	return cert, nil
}
func (m *mockTarget) Close() error { return nil }

func TestRegisterAndCreate(t *testing.T) {
	original := make(map[string]Factory)
	for k, v := range registry {
		original[k] = v
	}
	t.Cleanup(func() {
		registry = original
	})

	Register("mock", func(url string, insecure bool) (Target, error) {
		return &mockTarget{}, nil
	})

	target, err := Create("mock", "https://example.com", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if target == nil {
		t.Fatal("expected non-nil target")
	}
}

func TestCreate_UnknownType(t *testing.T) {
	_, err := Create("nonexistent", "https://example.com", false)
	if err == nil {
		t.Fatal("expected error for unknown target type")
	}
}

func TestCreate_FactoryError(t *testing.T) {
	original := make(map[string]Factory)
	for k, v := range registry {
		original[k] = v
	}
	t.Cleanup(func() {
		registry = original
	})

	Register("failing", func(url string, insecure bool) (Target, error) {
		return nil, fmt.Errorf("factory error")
	})

	_, err := Create("failing", "https://example.com", false)
	if err == nil {
		t.Fatal("expected error from factory")
	}
}

func TestCreate_InsecurePassedThrough(t *testing.T) {
	original := make(map[string]Factory)
	for k, v := range registry {
		original[k] = v
	}
	t.Cleanup(func() {
		registry = original
	})

	var gotInsecure bool
	Register("insecure-check", func(url string, insecure bool) (Target, error) {
		gotInsecure = insecure
		return &mockTarget{}, nil
	})

	Create("insecure-check", "https://example.com", true)
	if !gotInsecure {
		t.Error("expected insecure=true to be passed through to factory")
	}
}
