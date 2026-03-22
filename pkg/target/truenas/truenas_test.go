package truenas

import (
	"os"
	"testing"
)

func TestBuildWSURL_HTTPS(t *testing.T) {
	wsURL, err := buildWSURL("https://truenas.local:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsURL != "wss://truenas.local:443/api/current" {
		t.Errorf("got %q, want wss://truenas.local:443/api/current", wsURL)
	}
}

func TestBuildWSURL_HTTP(t *testing.T) {
	wsURL, err := buildWSURL("http://truenas.local:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsURL != "ws://truenas.local:80/api/current" {
		t.Errorf("got %q, want ws://truenas.local:80/api/current", wsURL)
	}
}

func TestBuildWSURL_DefaultPort(t *testing.T) {
	wsURL, err := buildWSURL("https://truenas.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsURL != "wss://truenas.local/api/current" {
		t.Errorf("got %q, want wss://truenas.local/api/current", wsURL)
	}
}

func TestBuildWSURL_NoHost(t *testing.T) {
	_, err := buildWSURL("https://")
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

func TestBuildWSURL_WithPath(t *testing.T) {
	// Path should be ignored; we always use /api/current
	wsURL, err := buildWSURL("https://truenas.local/some/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsURL != "wss://truenas.local/api/current" {
		t.Errorf("got %q, want wss://truenas.local/api/current", wsURL)
	}
}

func TestNewTrueNAS_MissingAPIKey(t *testing.T) {
	os.Unsetenv(envAPIKey)

	_, err := newTrueNAS("https://truenas.local", false)
	if err == nil {
		t.Fatal("expected error when API key env var is missing")
	}
}

func TestNewTrueNAS_WithAPIKey(t *testing.T) {
	t.Setenv(envAPIKey, "test-api-key")

	target, err := newTrueNAS("https://truenas.local", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tn, ok := target.(*TrueNAS)
	if !ok {
		t.Fatal("expected *TrueNAS type")
	}
	if tn.apiKey != "test-api-key" {
		t.Errorf("apiKey = %q, want %q", tn.apiKey, "test-api-key")
	}
	if tn.wsURL != "wss://truenas.local/api/current" {
		t.Errorf("wsURL = %q, want %q", tn.wsURL, "wss://truenas.local/api/current")
	}
}

func TestNewTrueNAS_Insecure(t *testing.T) {
	t.Setenv(envAPIKey, "test-api-key")

	target, err := newTrueNAS("https://truenas.local", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tn := target.(*TrueNAS)
	if !tn.insecure {
		t.Error("expected insecure=true")
	}
}

func TestNewTrueNAS_InvalidURL(t *testing.T) {
	t.Setenv(envAPIKey, "test-api-key")

	_, err := newTrueNAS("https://", true)
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

func TestSanitizeCertName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with-dash", "with-dash"},
		{"with_underscore", "with_underscore"},
		{"truenas.lab.yuha0.com-1234567890", "truenas_lab_yuha0_com-1234567890"},
		{"has spaces", "has_spaces"},
		{"special!@#$chars", "special____chars"},
		{"MiXeD-CaSe_123", "MiXeD-CaSe_123"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeCertName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeCertName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestClose_NilClient(t *testing.T) {
	tn := &TrueNAS{}
	if err := tn.Close(); err != nil {
		t.Errorf("Close with nil client should not error, got: %v", err)
	}
}
