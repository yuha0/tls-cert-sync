package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/tlscertsync/pkg/certutil"
	"github.com/tlscertsync/pkg/health"
	"github.com/tlscertsync/pkg/metrics"
	"github.com/tlscertsync/pkg/target"
	_ "github.com/tlscertsync/pkg/target/truenas"
)

var Version = "v1.0.0"

var (
	certDir    string
	targetType string
	targetURL  string
	interval   int
	insecure   bool
	logLevel   string
)

var rootCmd = &cobra.Command{
	Use:     "tlscertsync",
	Short:   "Sync TLS certificates to remote systems",
	Long:    "Reads TLS certificate and key files from a local directory and deploys them to a configured remote system when they differ from the remote certificate.",
	Version: Version,
	RunE:    run,
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print version and exit")
	rootCmd.Flags().StringVarP(&certDir, "cert-dir", "c", ".", "Directory containing tls.crt and tls.key")
	rootCmd.Flags().StringVarP(&targetType, "type", "t", "", "Target system type (e.g., truenas)")
	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target system URL")
	rootCmd.Flags().IntVarP(&interval, "interval", "i", 300, "Scan interval in seconds")
	rootCmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "Skip TLS certificate verification when connecting to remote system")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")

	rootCmd.MarkFlagRequired("type")
	rootCmd.MarkFlagRequired("url")
}

func Execute() error {
	return rootCmd.Execute()
}

func initLogging() error {
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log level %q (must be debug, info, warn, or error)", logLevel)
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	return nil
}

func run(cmd *cobra.Command, args []string) error {
	if err := initLogging(); err != nil {
		return err
	}

	targetURL = strings.TrimRight(targetURL, "/")

	slog.Info("starting tlscertsync",
		"type", targetType,
		"url", targetURL,
		"cert_dir", certDir,
		"interval", interval,
		"insecure", insecure,
	)

	t, err := target.Create(targetType, targetURL, insecure)
	if err != nil {
		return fmt.Errorf("creating target: %w", err)
	}
	defer t.Close()

	h := health.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.Handler())
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		slog.Info("health/metrics server listening", "addr", ":8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reconcile(ctx, t, h)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case <-ticker.C:
			reconcile(ctx, t, h)
		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			srv.Shutdown(shutdownCtx)
			return nil
		}
	}
}

func reconcile(ctx context.Context, t target.Target, h *health.Health) {
	slog.Debug("starting reconcile")

	certPEM, keyPEM, localCert, err := certutil.ReadCertFiles(certDir)
	if err != nil {
		slog.Error("failed to read cert files", "error", err)
		h.SetCertFilesOK(false)
		return
	}
	h.SetCertFilesOK(true)

	cn := localCert.Subject.CommonName
	if cn == "" {
		cn = "tls-cert-sync"
	}
	certName := fmt.Sprintf("%s-%d", cn, time.Now().Unix())

	activeCert, err := t.EnsureCert(ctx, certPEM, keyPEM, localCert, certName)
	if err != nil {
		slog.Error("failed to ensure certificate", "error", err)
		h.SetRemoteOK(false)
		return
	}
	h.SetRemoteOK(true)

	metrics.Update(targetType, targetURL, activeCert)
}
