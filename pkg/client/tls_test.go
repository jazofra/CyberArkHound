package client

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func logonServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `"tls-token"`)
	}))
	t.Cleanup(server.Close)
	return server
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCABundleIsTrusted(t *testing.T) {
	var hits atomic.Int32
	server := logonServer(t, &hits)
	bundle := writeFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))

	client := NewClient(server.URL, "u", "p", false, bundle, testClient(server.URL).Logger)
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate with --ca-bundle: %v", err)
	}

	// Without the bundle the self-signed test certificate is not trusted.
	plain := NewClient(server.URL, "u", "p", false, "", testClient(server.URL).Logger)
	if err := plain.Authenticate(); err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("expected a certificate error without the bundle, got %v", err)
	}
}

func TestUnusableCABundleFailsBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	server := logonServer(t, &hits)
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "absent.pem"),
		"not PEM": writeFile(t, "junk.pem", []byte("not a certificate")),
	} {
		client := NewClient(server.URL, "u", "p", true, path, testClient(server.URL).Logger)
		if err := client.Authenticate(); err == nil {
			t.Errorf("%s bundle: expected an error", name)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("server received %d requests; an unusable CA bundle must stop the client first", hits.Load())
	}
}
