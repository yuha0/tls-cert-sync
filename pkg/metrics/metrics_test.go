package metrics

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func generateTestCert(cn string, serial int64, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		Issuer:       pkix.Name{CommonName: cn},
		SerialNumber: big.NewInt(serial),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

func getGaugeValue(gauge *prometheus.GaugeVec, labels prometheus.Labels) (float64, error) {
	var metric dto.Metric
	g, err := gauge.GetMetricWith(labels)
	if err != nil {
		return 0, err
	}
	g.Write(&metric)
	return *metric.Gauge.Value, nil
}

func TestUpdate_SetsIssuerMetric(t *testing.T) {
	now := time.Now()
	cert := generateTestCert("Test Issuer", 12345, now.Add(-time.Hour), now.Add(time.Hour))

	Update("truenas", "https://truenas.local", cert)

	val, err := getGaugeValue(CertIssuer, prometheus.Labels{
		"target_type": "truenas",
		"target_url":  "https://truenas.local",
		"name":        "Test Issuer",
	})
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	if val != 1 {
		t.Errorf("expected issuer gauge = 1, got %f", val)
	}
}

func TestUpdate_SetsSerialNumberMetric(t *testing.T) {
	now := time.Now()
	cert := generateTestCert("Test Issuer", 0xABCD, now, now.Add(time.Hour))

	Update("truenas", "https://truenas.local", cert)

	val, err := getGaugeValue(CertSN, prometheus.Labels{
		"target_type":   "truenas",
		"target_url":    "https://truenas.local",
		"serial_number": fmt.Sprintf("%X", cert.SerialNumber),
	})
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	if val != 1 {
		t.Errorf("expected SN gauge = 1, got %f", val)
	}
}

func TestUpdate_SetsTimestampMetrics(t *testing.T) {
	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := generateTestCert("Test", 1, notBefore, notAfter)

	Update("truenas", "https://truenas.local", cert)

	labels := prometheus.Labels{
		"target_type": "truenas",
		"target_url":  "https://truenas.local",
	}

	nbVal, err := getGaugeValue(CertNotBefore, labels)
	if err != nil {
		t.Fatalf("failed to get NotBefore metric: %v", err)
	}
	if int64(nbVal) != notBefore.Unix() {
		t.Errorf("NotBefore = %v, want %v", int64(nbVal), notBefore.Unix())
	}

	naVal, err := getGaugeValue(CertNotAfter, labels)
	if err != nil {
		t.Fatalf("failed to get NotAfter metric: %v", err)
	}
	if int64(naVal) != notAfter.Unix() {
		t.Errorf("NotAfter = %v, want %v", int64(naVal), notAfter.Unix())
	}
}

func TestUpdate_EmptyIssuerCN_FallsBackToString(t *testing.T) {
	cert := &x509.Certificate{
		Issuer:       pkix.Name{Organization: []string{"Test Org"}},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	Update("truenas", "https://truenas.local", cert)

	// When CN is empty, it falls back to Issuer.String()
	val, err := getGaugeValue(CertIssuer, prometheus.Labels{
		"target_type": "truenas",
		"target_url":  "https://truenas.local",
		"name":        cert.Issuer.String(),
	})
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	if val != 1 {
		t.Errorf("expected issuer gauge = 1, got %f", val)
	}
}

func TestUpdate_ReplacesOldLabels(t *testing.T) {
	now := time.Now()
	cert1 := generateTestCert("Issuer A", 111, now, now.Add(time.Hour))
	cert2 := generateTestCert("Issuer B", 222, now, now.Add(time.Hour))

	Update("truenas", "https://truenas.local", cert1)
	Update("truenas", "https://truenas.local", cert2)

	// New issuer should exist
	val, err := getGaugeValue(CertIssuer, prometheus.Labels{
		"target_type": "truenas",
		"target_url":  "https://truenas.local",
		"name":        "Issuer B",
	})
	if err != nil {
		t.Fatalf("failed to get new metric: %v", err)
	}
	if val != 1 {
		t.Errorf("expected new issuer gauge = 1, got %f", val)
	}

	// Old issuer label combination should have been deleted.
	// Check via Collect since GetMetricWith would re-create the metric.
	ch := make(chan prometheus.Metric, 10)
	CertIssuer.Collect(ch)
	close(ch)
	for m := range ch {
		var metric dto.Metric
		m.Write(&metric)
		for _, lp := range metric.Label {
			if *lp.Name == "name" && *lp.Value == "Issuer A" {
				t.Error("old issuer label 'Issuer A' should have been deleted")
			}
		}
	}
}

func TestUpdate_DifferentTargets_Independent(t *testing.T) {
	now := time.Now()
	cert1 := generateTestCert("Issuer1", 1, now, now.Add(time.Hour))
	cert2 := generateTestCert("Issuer2", 2, now, now.Add(time.Hour))

	Update("truenas", "https://host1", cert1)
	Update("truenas", "https://host2", cert2)

	// Both should exist independently
	val1, err := getGaugeValue(CertIssuer, prometheus.Labels{
		"target_type": "truenas",
		"target_url":  "https://host1",
		"name":        "Issuer1",
	})
	if err != nil {
		t.Fatalf("failed to get host1 metric: %v", err)
	}
	if val1 != 1 {
		t.Error("expected host1 issuer = 1")
	}

	val2, err := getGaugeValue(CertIssuer, prometheus.Labels{
		"target_type": "truenas",
		"target_url":  "https://host2",
		"name":        "Issuer2",
	})
	if err != nil {
		t.Fatalf("failed to get host2 metric: %v", err)
	}
	if val2 != 1 {
		t.Error("expected host2 issuer = 1")
	}
}

