package health

import (
	"encoding/json"
	"net/http"
	"sync"
)

type Health struct {
	mu          sync.RWMutex
	certFilesOK bool
	remoteOK    bool
}

func New() *Health {
	return &Health{}
}

func (h *Health) SetCertFilesOK(ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certFilesOK = ok
}

func (h *Health) SetRemoteOK(ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.remoteOK = ok
}

func (h *Health) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		certOK := h.certFilesOK
		remoteOK := h.remoteOK
		h.mu.RUnlock()

		resp := map[string]interface{}{
			"ready":        certOK && remoteOK,
			"cert_files_ok": certOK,
			"remote_ok":    remoteOK,
		}

		w.Header().Set("Content-Type", "application/json")
		if certOK && remoteOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(resp)
	}
}
