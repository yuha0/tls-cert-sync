package truenas

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/tlscertsync/pkg/target"
	truenas_api "github.com/truenas/api_client_golang/truenas_api"
)

const envAPIKey = "SYNC_TRUENAS_API_KEY"

// unwrapResult extracts the "result" field from a JSON-RPC response wrapper.
func unwrapResult(raw json.RawMessage) json.RawMessage {
	var wrapper struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.Result != nil {
		return wrapper.Result
	}
	return raw
}

func unwrapResultArray(raw json.RawMessage) ([]map[string]interface{}, error) {
	data := unwrapResult(raw)
	var result []map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func unwrapResultObject(raw json.RawMessage) (map[string]interface{}, error) {
	data := unwrapResult(raw)
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func init() {
	target.Register("truenas", newTrueNAS)
}

type TrueNAS struct {
	wsURL    string
	apiKey   string
	insecure bool
	client   *truenas_api.Client
}

func newTrueNAS(rawURL string, insecure bool) (target.Target, error) {
	apiKey := os.Getenv(envAPIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("environment variable %s is required for truenas target type", envAPIKey)
	}

	wsURL, err := buildWSURL(rawURL)
	if err != nil {
		return nil, err
	}

	return &TrueNAS{
		wsURL:    wsURL,
		apiKey:   apiKey,
		insecure: insecure,
	}, nil
}

func buildWSURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing URL %q: %w", rawURL, err)
	}

	scheme := "wss"
	if u.Scheme == "http" {
		scheme = "ws"
	}

	host := u.Host
	if host == "" {
		return "", fmt.Errorf("URL %q has no host", rawURL)
	}

	return fmt.Sprintf("%s://%s/api/current", scheme, host), nil
}

func (t *TrueNAS) Connect(ctx context.Context) error {
	slog.Debug("connecting to TrueNAS", "url", t.wsURL)
	client, err := truenas_api.NewClient(t.wsURL, !t.insecure)
	if err != nil {
		return fmt.Errorf("connecting to TrueNAS at %s: %w", t.wsURL, err)
	}

	if err := client.Login("", "", t.apiKey); err != nil {
		client.Close()
		return fmt.Errorf("authenticating with TrueNAS: %w", err)
	}

	if err := client.SubscribeToJobs(); err != nil {
		client.Close()
		return fmt.Errorf("subscribing to TrueNAS jobs: %w", err)
	}

	slog.Debug("connected to TrueNAS")
	t.client = client
	return nil
}

func (t *TrueNAS) closeClient() {
	if t.client != nil {
		t.client.Close()
		t.client = nil
	}
}

// sanitizeCertName replaces invalid characters with underscores to comply with TrueNAS naming rules.
func sanitizeCertName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

type certEntry struct {
	id   float64
	name string
	cert *x509.Certificate
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func (t *TrueNAS) queryCerts() ([]certEntry, error) {
	res, err := t.client.Call("certificate.query", 30, []interface{}{[]interface{}{}})
	if err != nil {
		return nil, fmt.Errorf("querying certificates: %w", err)
	}

	slog.Debug("certificate.query raw response", "body", truncate(string(res), 500))

	rawCerts, err := unwrapResultArray(res)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate list: %w", err)
	}

	var entries []certEntry
	for _, c := range rawCerts {
		id, _ := c["id"].(float64)
		name, _ := c["name"].(string)
		certPEM, _ := c["certificate"].(string)

		entry := certEntry{id: id, name: name}
		if certPEM != "" {
			block, _ := pem.Decode([]byte(certPEM))
			if block != nil {
				parsed, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					entry.cert = parsed
				}
			}
		}
		slog.Debug("certificate entry", "id", id, "name", name, "has_cert", entry.cert != nil)
		entries = append(entries, entry)
	}

	slog.Debug("queried certificates", "count", len(entries))
	return entries, nil
}

func (t *TrueNAS) getActiveUICertID() (float64, error) {
	res, err := t.client.Call("system.general.config", 30, []interface{}{})
	if err != nil {
		return 0, fmt.Errorf("querying system.general.config: %w", err)
	}

	slog.Debug("system.general.config raw response", "body", truncate(string(res), 500))

	config, err := unwrapResultObject(res)
	if err != nil {
		return 0, fmt.Errorf("parsing system.general.config: %w", err)
	}

	slog.Debug("ui_certificate field", "value", fmt.Sprintf("%v", config["ui_certificate"]), "type", fmt.Sprintf("%T", config["ui_certificate"]))

	var id float64
	switch v := config["ui_certificate"].(type) {
	case float64:
		id = v
	case map[string]interface{}:
		certID, ok := v["id"].(float64)
		if !ok {
			return 0, fmt.Errorf("ui_certificate object missing 'id' field")
		}
		id = certID
	default:
		return 0, fmt.Errorf("ui_certificate has unexpected type %T", config["ui_certificate"])
	}

	slog.Debug("active UI certificate", "id", id)
	return id, nil
}

func (t *TrueNAS) EnsureCert(ctx context.Context, certPEM []byte, keyPEM []byte, cert *x509.Certificate, certName string) (*x509.Certificate, error) {
	certName = sanitizeCertName(certName)

	if err := t.Connect(ctx); err != nil {
		return nil, err
	}
	defer t.closeClient()

	certs, err := t.queryCerts()
	if err != nil {
		return nil, err
	}

	var matchingID float64
	var found bool
	for _, c := range certs {
		if c.cert != nil && bytes.Equal(c.cert.Raw, cert.Raw) {
			matchingID = c.id
			found = true
			slog.Info("certificate already imported", "name", c.name, "id", c.id)
			break
		}
	}

	if !found {
		slog.Info("importing certificate", "name", certName)
		id, err := t.importCert(certName, certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		matchingID = id
	}

	activeID, err := t.getActiveUICertID()
	if err != nil {
		return nil, err
	}

	if activeID == matchingID {
		slog.Info("certificate is already active, no action needed", "id", matchingID)
		for _, c := range certs {
			if c.id == activeID && c.cert != nil {
				return c.cert, nil
			}
		}
		return cert, nil
	}

	slog.Info("updating active UI certificate", "from_id", activeID, "to_id", matchingID)
	updateParams := []interface{}{
		map[string]interface{}{
			"ui_certificate": matchingID,
		},
	}
	_, err = t.client.Call("system.general.update", 30, updateParams)
	if err != nil {
		return nil, fmt.Errorf("calling system.general.update: %w", err)
	}

	t.client.Call("system.general.ui_restart", 10, []interface{}{0})

	slog.Info("restarted web service with new certificate", "id", matchingID)

	if !found {
		t.cleanupOldCerts(certName, certs)
	}

	return cert, nil
}

func (t *TrueNAS) importCert(certName string, certPEM []byte, keyPEM []byte) (float64, error) {
	createParams := []interface{}{
		map[string]interface{}{
			"name":        certName,
			"create_type": "CERTIFICATE_CREATE_IMPORTED",
			"certificate": string(certPEM),
			"privatekey":  string(keyPEM),
		},
	}

	job, err := t.client.CallWithJob("certificate.create", createParams, func(progress float64, state string, desc string) {
		slog.Debug("certificate.create progress", "progress", progress, "state", state, "desc", desc)
	})
	if err != nil {
		return 0, fmt.Errorf("calling certificate.create: %w", err)
	}

	result := <-job.DoneCh
	if result != "" {
		return 0, fmt.Errorf("certificate.create job failed: %s", result)
	}

	certResult, ok := job.Result.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("unexpected certificate.create result type: %T", job.Result)
	}

	certID, ok := certResult["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("certificate.create result missing or invalid 'id' field")
	}

	slog.Info("imported certificate", "name", certName, "id", certID)
	return certID, nil
}

// cleanupOldCerts keeps at most 2 certs with the same name prefix, deleting the rest.
func (t *TrueNAS) cleanupOldCerts(newCertName string, certs []certEntry) {
	lastDash := strings.LastIndex(newCertName, "-")
	if lastDash < 0 {
		return
	}
	prefix := newCertName[:lastDash+1]

	var matching []certEntry
	for _, c := range certs {
		if strings.HasPrefix(c.name, prefix) {
			matching = append(matching, c)
		}
	}

	if len(matching) <= 1 {
		return
	}

	sort.Slice(matching, func(i, j int) bool {
		return matching[i].id > matching[j].id
	})

	for _, c := range matching[1:] {
		slog.Info("deleting old certificate", "name", c.name, "id", c.id)
		deleteParams := []interface{}{int(c.id), true}
		if _, err := t.client.Call("certificate.delete", 30, deleteParams); err != nil {
			slog.Warn("failed to delete certificate", "name", c.name, "error", err)
		}
	}
}

func (t *TrueNAS) Close() error {
	t.closeClient()
	return nil
}
