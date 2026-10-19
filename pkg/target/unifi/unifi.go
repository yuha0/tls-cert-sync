package unifi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"

	"github.com/tlscertsync/pkg/target"
)

const (
	envUsername = "SYNC_UNIFI_USERNAME"
	envPassword = "SYNC_UNIFI_PASSWORD"
)

func init() {
	target.Register("unifi", newUniFi)
}

type UniFi struct {
	baseURL  string
	username string
	password string
	insecure bool
}

func newUniFi(rawURL string, insecure bool) (target.Target, error) {
	username := os.Getenv(envUsername)
	if username == "" {
		return nil, fmt.Errorf("environment variable %s is required for unifi target type", envUsername)
	}
	password := os.Getenv(envPassword)
	if password == "" {
		return nil, fmt.Errorf("environment variable %s is required for unifi target type", envPassword)
	}

	return &UniFi{
		baseURL:  rawURL,
		username: username,
		password: password,
		insecure: insecure,
	}, nil
}

// client is an authenticated HTTP client for the UniFi OS API.
type client struct {
	baseURL    string
	csrfToken  string
	httpClient *http.Client
}

func newClient(baseURL string, insecure bool) (*client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	return &client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Jar: jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *client) login(username, password string) error {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	req, err := http.NewRequest("POST", c.baseURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("login: %w", target.ErrRateLimited)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	c.csrfToken = resp.Header.Get("X-Csrf-Token")
	slog.Debug("logged in to UniFi", "csrf_token_present", c.csrfToken != "")
	return nil
}

func (c *client) do(method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.csrfToken != "" {
		req.Header.Set("X-Csrf-Token", c.csrfToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if newToken := resp.Header.Get("X-Updated-Csrf-Token"); newToken != "" {
		c.csrfToken = newToken
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}

	slog.Debug("UniFi API response", "method", method, "path", path, "status", resp.StatusCode)
	return respBody, resp.StatusCode, nil
}

type certInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Fingerprint string `json:"fingerprint"`
}

func (c *client) listCerts() ([]certInfo, error) {
	body, status, err := c.do("GET", "/api/userCertificates", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("listing certificates: status %d, body: %s", status, truncate(string(body), 200))
	}

	slog.Debug("userCertificates response", "body", truncate(string(body), 500))

	var certs []certInfo
	if err := json.Unmarshal(body, &certs); err != nil {
		return nil, fmt.Errorf("parsing certificate list: %w", err)
	}
	return certs, nil
}

func (c *client) uploadCert(name string, certPEM, keyPEM []byte) (*certInfo, error) {
	payload := map[string]string{
		"name": name,
		"cert": string(certPEM),
		"key":  string(keyPEM),
	}

	body, status, err := c.do("POST", "/api/userCertificates", payload)
	if err != nil {
		return nil, err
	}

	slog.Debug("uploadCert response", "status", status, "body", truncate(string(body), 500))

	// Duplicate cert returns 409 or 400 with "DUPLICATE"
	if status == http.StatusConflict || (status == http.StatusBadRequest && strings.Contains(string(body), "DUPLICATE")) {
		slog.Debug("certificate is a duplicate, already uploaded")
		return nil, nil
	}

	if status != http.StatusOK && status != http.StatusCreated {
		return nil, fmt.Errorf("uploading certificate: status %d, body: %s", status, truncate(string(body), 200))
	}

	var cert certInfo
	if err := json.Unmarshal(body, &cert); err != nil {
		return nil, fmt.Errorf("parsing upload response: %w", err)
	}
	return &cert, nil
}

func (c *client) activateCert(id string) error {
	payload := map[string]bool{"active": true}
	body, status, err := c.do("PUT", "/api/userCertificates/"+id+"/status", payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("activating certificate: status %d, body: %s", status, truncate(string(body), 200))
	}
	return nil
}

func (u *UniFi) connect() (*client, error) {
	c, err := newClient(u.baseURL, u.insecure)
	if err != nil {
		return nil, err
	}
	if err := c.login(u.username, u.password); err != nil {
		return nil, err
	}
	return c, nil
}

// certFingerprint computes the SHA-1 fingerprint of a DER-encoded certificate,
// formatted as colon-separated uppercase hex pairs to match the UniFi API format.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (u *UniFi) EnsureCert(ctx context.Context, certPEM []byte, keyPEM []byte, cert *x509.Certificate, certName string) (*x509.Certificate, error) {
	c, err := u.connect()
	if err != nil {
		return nil, err
	}

	localFP := certFingerprint(cert)
	slog.Debug("local certificate fingerprint", "fingerprint", localFP)

	certs, err := c.listCerts()
	if err != nil {
		return nil, err
	}

	for _, ci := range certs {
		slog.Debug("remote certificate", "id", ci.ID, "name", ci.Name, "active", ci.Active, "fingerprint", ci.Fingerprint)
	}

	// Check if local cert is already uploaded by fingerprint
	var matchingCert *certInfo
	for i, ci := range certs {
		if ci.Fingerprint == localFP {
			matchingCert = &certs[i]
			slog.Info("certificate already uploaded", "id", ci.ID, "name", ci.Name, "active", ci.Active)
			break
		}
	}

	if matchingCert == nil {
		// Upload new cert
		slog.Info("importing certificate", "name", certName)
		uploaded, err := c.uploadCert(certName, certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		if uploaded == nil {
			return nil, fmt.Errorf("upload returned nil (unexpected duplicate)")
		}
		slog.Info("uploaded certificate", "name", certName, "id", uploaded.ID)
		matchingCert = uploaded
	}

	if matchingCert.Active {
		slog.Info("certificate is already active, no action needed", "id", matchingCert.ID)
		return cert, nil
	}

	slog.Info("activating certificate", "id", matchingCert.ID)
	if err := c.activateCert(matchingCert.ID); err != nil {
		return nil, err
	}
	slog.Info("activated certificate", "id", matchingCert.ID)

	deleteOldCerts(c, certName, matchingCert.ID, certs)

	return cert, nil
}

// deleteOldCerts deletes all certs matching the naming convention except the active one.
func deleteOldCerts(c *client, certName string, activeID string, oldCerts []certInfo) {
	lastDash := strings.LastIndex(certName, "-")
	if lastDash < 0 {
		return
	}
	prefix := certName[:lastDash+1]

	for _, ci := range oldCerts {
		if !strings.HasPrefix(ci.Name, prefix) {
			continue
		}
		if ci.ID == activeID {
			continue
		}
		slog.Info("deleting old certificate", "name", ci.Name, "id", ci.ID)
		body, status, err := c.do("DELETE", "/api/userCertificates/"+ci.ID, nil)
		if err != nil {
			slog.Warn("failed to delete certificate", "name", ci.Name, "error", err)
		} else if status < 200 || status > 299 {
			slog.Warn("failed to delete certificate", "name", ci.Name, "status", status, "body", truncate(string(body), 200))
		}
	}
}

func (u *UniFi) Close() error {
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

