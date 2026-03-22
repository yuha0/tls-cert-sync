package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_NotReady(t *testing.T) {
	h := New()
	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["ready"] != false {
		t.Error("expected ready=false")
	}
	if body["cert_files_ok"] != false {
		t.Error("expected cert_files_ok=false")
	}
	if body["remote_ok"] != false {
		t.Error("expected remote_ok=false")
	}
}

func TestHandler_Ready(t *testing.T) {
	h := New()
	h.SetCertFilesOK(true)
	h.SetRemoteOK(true)

	handler := h.Handler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["ready"] != true {
		t.Error("expected ready=true")
	}
}

func TestHandler_PartialReady_CertOnly(t *testing.T) {
	h := New()
	h.SetCertFilesOK(true)

	handler := h.Handler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	if body["cert_files_ok"] != true {
		t.Error("expected cert_files_ok=true")
	}
	if body["remote_ok"] != false {
		t.Error("expected remote_ok=false")
	}
}

func TestHandler_SetBackToFalse(t *testing.T) {
	h := New()
	h.SetCertFilesOK(true)
	h.SetRemoteOK(true)

	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("expected 200 when both OK")
	}

	h.SetRemoteOK(false)
	rec = httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Error("expected 503 after setting remoteOK to false")
	}
}

func TestHandler_ContentType(t *testing.T) {
	h := New()
	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}
