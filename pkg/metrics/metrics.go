package metrics

import (
	"crypto/x509"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	CertIssuer = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tlscertsync_target_cert_issuer",
		Help: "Set to 1 if the target certificate has a valid issuer. The issuer name is in the 'name' label.",
	}, []string{"target_type", "target_url", "name"})

	CertSN = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tlscertsync_target_cert_sn",
		Help: "Set to 1 if the target certificate has a valid serial number. The serial number is in the 'serial_number' label.",
	}, []string{"target_type", "target_url", "serial_number"})

	CertNotBefore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tlscertsync_target_cert_notbefore",
		Help: "The NotBefore timestamp of the target certificate.",
	}, []string{"target_type", "target_url"})

	CertNotAfter = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tlscertsync_target_cert_notafter",
		Help: "The NotAfter timestamp of the target certificate.",
	}, []string{"target_type", "target_url"})
)

func init() {
	prometheus.MustRegister(CertIssuer)
	prometheus.MustRegister(CertSN)
	prometheus.MustRegister(CertNotBefore)
	prometheus.MustRegister(CertNotAfter)
}

// Update sets all certificate metrics from the given remote certificate.
func Update(targetType, targetURL string, cert *x509.Certificate) {
	// Delete only the label combinations for this target to avoid scrape gaps
	CertIssuer.DeletePartialMatch(prometheus.Labels{"target_type": targetType, "target_url": targetURL})
	CertSN.DeletePartialMatch(prometheus.Labels{"target_type": targetType, "target_url": targetURL})

	issuerName := cert.Issuer.CommonName
	if issuerName == "" {
		issuerName = cert.Issuer.String()
	}
	CertIssuer.WithLabelValues(targetType, targetURL, issuerName).Set(1)

	serialNumber := fmt.Sprintf("%X", cert.SerialNumber)
	CertSN.WithLabelValues(targetType, targetURL, serialNumber).Set(1)

	CertNotBefore.WithLabelValues(targetType, targetURL).Set(float64(cert.NotBefore.Unix()))
	CertNotAfter.WithLabelValues(targetType, targetURL).Set(float64(cert.NotAfter.Unix()))
}
