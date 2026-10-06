package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

func quietLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

func mustParse(t *testing.T, args ...string) *config {
	t.Helper()
	cfg, err := parseFlags(args)
	if err != nil {
		t.Fatalf("parseFlags(%v): %v", args, err)
	}
	return cfg
}

func TestParseFlagsRequiresCoreFlags(t *testing.T) {
	_, err := parseFlags([]string{"--pvwa", "pvwa.example.com"})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("expected a usage error, got %v", err)
	}
	for _, flag := range []string{"--output", "--target-domains", "--username"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error %q should mention %s", err, flag)
		}
	}
}

func TestParseFlagsFromRawNeedsNoServer(t *testing.T) {
	cfg := mustParse(t, "--from-raw", "raw.json", "--output", "out.json", "--target-domains", "corp.local")
	if cfg.fromRaw != "raw.json" {
		t.Fatalf("fromRaw = %q", cfg.fromRaw)
	}
	if _, err := parseFlags([]string{"--from-raw", "a", "--save-raw", "b", "--output", "o", "--target-domains", "d"}); err == nil {
		t.Fatal("--from-raw with --save-raw should be rejected")
	}
}

func TestParseFlagsLogLevel(t *testing.T) {
	base := []string{"--pvwa", "p", "--username", "u", "--output", "o", "--target-domains", "d"}
	tests := []struct {
		extra []string
		want  logrus.Level
	}{
		{nil, logrus.InfoLevel},
		{[]string{"--log-level", "debug"}, logrus.DebugLevel},
		{[]string{"--log-level", "WARNING"}, logrus.WarnLevel},
		{[]string{"--log-level", "Error"}, logrus.ErrorLevel},
		{[]string{"--quiet"}, logrus.WarnLevel},
		{[]string{"--quiet", "--log-level", "ERROR"}, logrus.ErrorLevel},
		{[]string{"--quiet", "--debug"}, logrus.DebugLevel},
	}
	for _, tt := range tests {
		cfg := mustParse(t, append(append([]string{}, base...), tt.extra...)...)
		if cfg.logLevel != tt.want {
			t.Errorf("%v: level = %s, want %s", tt.extra, cfg.logLevel, tt.want)
		}
	}
	if _, err := parseFlags(append(base, "--log-level", "verbose")); err == nil {
		t.Error("unknown --log-level should be rejected")
	}
}

func TestParseFlagsNormalizesTargetDomains(t *testing.T) {
	cfg := mustParse(t, "--pvwa", "p", "--username", "u", "--output", "o",
		"--target-domains", "corp.local, sub.corp.local.,", "extra.local")
	want := []string{"corp.local", "sub.corp.local", "extra.local"}
	if !reflect.DeepEqual(cfg.targetDomains, want) {
		t.Fatalf("targetDomains = %q, want %q", cfg.targetDomains, want)
	}
}

func TestParseFlagsIdentityNeedsTenantURL(t *testing.T) {
	_, err := parseFlags([]string{"--pvwa", "p", "--username", "u", "--output", "o", "--target-domains", "d", "--auth-method", "identity"})
	if err == nil || !strings.Contains(err.Error(), "--identity-url") {
		t.Fatalf("expected --identity-url error, got %v", err)
	}
}

func TestResolvePassword(t *testing.T) {
	env := func(v string) func(string) string {
		return func(key string) string {
			if key == passwordEnvVar {
				return v
			}
			return ""
		}
	}
	prompt := func(v string) func() (string, error) { return func() (string, error) { return v, nil } }

	cfg := &config{password: "flag", passwordFlag: true}
	if err := resolvePassword(cfg, env("env"), prompt("typed")); err != nil || cfg.password != "flag" {
		t.Errorf("--password should win: %q, %v", cfg.password, err)
	}
	cfg = &config{}
	if err := resolvePassword(cfg, env("env"), prompt("typed")); err != nil || cfg.password != "env" {
		t.Errorf("environment should beat the prompt: %q, %v", cfg.password, err)
	}
	cfg = &config{}
	if err := resolvePassword(cfg, env(""), prompt("typed")); err != nil || cfg.password != "typed" {
		t.Errorf("prompt should be used last: %q, %v", cfg.password, err)
	}
	if err := resolvePassword(&config{}, env(""), nil); err == nil || !strings.Contains(err.Error(), passwordEnvVar) {
		t.Errorf("no source should be an error naming %s, got %v", passwordEnvVar, err)
	}
	if err := resolvePassword(&config{}, env(""), prompt("")); err == nil {
		t.Error("empty prompted password should be rejected")
	}
}

// fakePVWA is a minimal in-memory PVWA serving one safe, one account, two
// users and one group.
type fakePVWA struct {
	*httptest.Server
	loggedOff     atomic.Bool
	memberFilters sync.Map // filter query values seen on safe-member requests
	// onSafeMembers, if set, runs before each safe-members response.
	onSafeMembers func()
	// failUsers makes the users endpoints fail.
	failUsers bool
}

func newFakePVWA(t *testing.T) *fakePVWA {
	f := &fakePVWA{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		write := func(body string) { _, _ = io.WriteString(w, body) }
		switch r.URL.Path {
		case "/PasswordVault/API/Auth/CyberArk/Logon":
			write(`"session-token"`)
			return
		case "/PasswordVault/API/Auth/Logoff":
			f.loggedOff.Store(true)
			write(`{}`)
			return
		}
		if r.Header.Get("Authorization") != "session-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/PasswordVault/API/Users":
			if f.failUsers {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			write(`{"Users":[{"id":1,"username":"alice","groupsMembership":[{"groupName":"Ops"}]},{"id":2,"username":"bob"}]}`)
		case "/PasswordVault/API/UserGroups":
			write(`{"value":[{"id":10,"groupName":"Ops"}]}`)
		case "/PasswordVault/API/UserGroups/10":
			write(`{"id":10,"groupName":"Ops","members":[{"username":"alice"},{"username":"bob"}]}`)
		case "/PasswordVault/API/safes":
			write(`{"value":[{"safeName":"Prod","safeUrlId":"Prod"}]}`)
		case "/PasswordVault/API/Safes/Prod/Members":
			f.memberFilters.Store(r.URL.Query().Get("filter"), true)
			if f.onSafeMembers != nil {
				f.onSafeMembers()
			}
			write(`{"value":[
				{"memberName":"Ops","memberType":"Group","safeName":"Prod","permissions":{"useAccounts":true,"retrieveAccounts":true}},
				{"memberName":"Vault Admins","memberType":"Group","safeName":"Prod","permissions":{"manageSafeMembers":true}}]}`)
		case "/PasswordVault/API/Accounts":
			write(`{"value":[{"id":"1_1"}],"count":1}`)
		case "/PasswordVault/API/Accounts/1_1":
			write(`{"id":"1_1","userName":"svc","address":"srv01.corp.local","safeName":"Prod","platformId":"WinServer"}`)
		case "/PasswordVault/API/Accounts/1_1/Activities":
			write(`{"Activities":[{"User":"alice","Action":"Retrieve password","Date":4102444800}]}`)
		case "/PasswordVault/API/Platforms/":
			write(`{"Platforms":[{"general":{"id":"WinServer","name":"WinServer"}}]}`)
		case "/PasswordVault/API/Platforms/Targets/WinServer/PrivilegedSessionManagement":
			write(`{"PSMConnectors":[]}`)
		case "/PasswordVault/API/Platforms/Targets":
			write(`{"Platforms":[]}`)
		case "/PasswordVault/API/PSM/Servers/":
			write(`{"PSMServers":[]}`)
		case "/PasswordVault/API/PSM/Connectors/":
			write(`{"PSMConnectors":[]}`)
		case "/PasswordVault/WebServices/PIMServices.svc/Applications/":
			write(`{"application":[]}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

type exportDoc struct {
	Graph struct {
		Nodes []struct {
			ID         string                 `json:"id"`
			Kinds      []string               `json:"kinds"`
			Properties map[string]interface{} `json:"properties"`
		} `json:"nodes"`
		Edges []struct {
			Kind  string            `json:"kind"`
			Start map[string]string `json:"start"`
			End   map[string]string `json:"end"`
		} `json:"edges"`
	} `json:"graph"`
}

func readExport(t *testing.T, path string) exportDoc {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var doc exportDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	return doc
}

func liveArgs(f *fakePVWA, dir string, extra ...string) []string {
	return append([]string{
		"--pvwa", f.URL, "--username", "collector", "--password", "secret",
		"--output", filepath.Join(dir, "out.json"), "--target-domains", "corp.local",
		"--workers", "4",
	}, extra...)
}

func TestRunEndToEndAndRebuildFromRaw(t *testing.T) {
	f := newFakePVWA(t)
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	findings := filepath.Join(dir, "findings.json")
	cfg := mustParse(t, liveArgs(f, dir, "--save-raw", raw, "--findings-output", findings)...)

	if code := run(context.Background(), cfg, quietLogger()); code != exitOK {
		t.Fatalf("run exit code = %d, want %d", code, exitOK)
	}
	if !f.loggedOff.Load() {
		t.Error("PVWA session was not logged off")
	}
	if _, ok := f.memberFilters.Load("includePredefinedUsers eq true"); !ok {
		t.Error("safe members were not requested with includePredefinedUsers")
	}

	doc := readExport(t, cfg.outputFile)
	names := map[string]bool{}
	for _, n := range doc.Graph.Nodes {
		if name, ok := n.Properties["name"].(string); ok {
			names[n.Kinds[0]+":"+name] = true
		}
	}
	for _, want := range []string{"CyberArk_User:alice", "CyberArk_User:bob", "CyberArk_Group:Ops", "CyberArk_Safe:Prod", "CyberArk_Account:svc", "CyberArk_Platform:WinServer"} {
		if !names[want] {
			t.Errorf("export is missing node %s", want)
		}
	}
	memberOf := 0
	for _, e := range doc.Graph.Edges {
		if e.Kind == "CyberArk_MemberOf" {
			memberOf++
		}
	}
	if memberOf != 2 {
		t.Errorf("MemberOf edges = %d, want 2 (alice from her details, bob from the group's member list)", memberOf)
	}

	var report findingsReport
	data, err := os.ReadFile(findings)
	if err != nil || json.Unmarshal(data, &report) != nil {
		t.Fatalf("findings report unreadable: %v", err)
	}
	if report.PVWATag == "" || report.Findings == nil {
		t.Errorf("findings report incomplete: %+v", report)
	}

	// Rebuilding from the raw collection must reproduce the export exactly.
	rebuilt := filepath.Join(dir, "rebuilt.json")
	rcfg := mustParse(t, "--from-raw", raw, "--output", rebuilt, "--target-domains", "corp.local")
	if code := run(context.Background(), rcfg, quietLogger()); code != exitOK {
		t.Fatalf("rebuild exit code = %d", code)
	}
	a, _ := os.ReadFile(cfg.outputFile)
	b, _ := os.ReadFile(rebuilt)
	if string(a) != string(b) {
		t.Error("export rebuilt from --save-raw differs from the live export")
	}
}

func TestRunInterruptedExportsPartialDataAndLogsOff(t *testing.T) {
	f := newFakePVWA(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Interrupt as soon as safe enumeration reaches the members phase.
	f.onSafeMembers = cancel

	dir := t.TempDir()
	cfg := mustParse(t, liveArgs(f, dir)...)
	if code := run(ctx, cfg, quietLogger()); code != exitInterrupted {
		t.Fatalf("exit code = %d, want %d", code, exitInterrupted)
	}
	if !f.loggedOff.Load() {
		t.Error("session must be logged off after an interrupted collection")
	}
	doc := readExport(t, cfg.outputFile)
	if len(doc.Graph.Nodes) == 0 {
		t.Error("partial export should contain the users, groups and safes collected before the interruption")
	}
}

func TestRunLogsOffWhenCollectionFails(t *testing.T) {
	f := newFakePVWA(t)
	f.failUsers = true
	dir := t.TempDir()
	cfg := mustParse(t, liveArgs(f, dir, "--max-reauth-attempts", "0")...)

	if code := run(context.Background(), cfg, quietLogger()); code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	if !f.loggedOff.Load() {
		t.Error("session must be logged off when the collection fails")
	}
	if _, err := os.Stat(cfg.outputFile); !os.IsNotExist(err) {
		t.Errorf("no export should be written after a failed collection (stat err: %v)", err)
	}
}

func TestParseFlagsHelp(t *testing.T) {
	if _, err := parseFlags([]string{"--help"}); !errors.Is(err, pflag.ErrHelp) {
		t.Fatalf("--help should return pflag.ErrHelp, got %v", err)
	}
}

func TestTLSHint(t *testing.T) {
	if hint := tlsHint(errors.New(`Post "https://pvwa/": tls: failed to verify certificate: x509: certificate signed by unknown authority`)); !strings.Contains(hint, "--ca-bundle") {
		t.Errorf("unknown-authority hint should point to --ca-bundle, got %q", hint)
	}
	if hint := tlsHint(errors.New("remote error: tls: handshake failure")); !strings.Contains(hint, "GODEBUG") {
		t.Errorf("handshake hint should point to GODEBUG, got %q", hint)
	}
	if hint := tlsHint(errors.New("authentication failed with HTTP 403: denied")); hint != "" {
		t.Errorf("non-TLS errors should get no hint, got %q", hint)
	}
}

func TestPVWATagFlag(t *testing.T) {
	base := []string{"--pvwa", "pvwa.example.com", "--username", "u", "--output", "o", "--target-domains", "d"}
	if cfg := mustParse(t, base...); pvwaTag(cfg) != "PVEX" {
		t.Errorf("derived tag = %q, want PVEX", pvwaTag(cfg))
	}
	if cfg := mustParse(t, append(base, "--pvwa-tag", "prod-eu")...); pvwaTag(cfg) != "PROD-EU" {
		t.Errorf("explicit tag = %q, want PROD-EU", pvwaTag(cfg))
	}
	for _, bad := range []string{"-x", "has space", "a/b", strings.Repeat("x", 33)} {
		if _, err := parseFlags(append(base, "--pvwa-tag", bad)); err == nil {
			t.Errorf("--pvwa-tag %q should be rejected", bad)
		}
	}
}

func TestFromRawCanRetag(t *testing.T) {
	f := newFakePVWA(t)
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	if code := run(context.Background(), mustParse(t, liveArgs(f, dir, "--save-raw", raw)...), quietLogger()); code != exitOK {
		t.Fatalf("collection exit code = %d", code)
	}
	out := filepath.Join(dir, "retagged.json")
	cfg := mustParse(t, "--from-raw", raw, "--output", out, "--target-domains", "corp.local", "--pvwa-tag", "vaultb")
	if code := run(context.Background(), cfg, quietLogger()); code != exitOK {
		t.Fatalf("rebuild exit code = %d", code)
	}
	doc := readExport(t, out)
	for _, n := range doc.Graph.Nodes {
		if !strings.HasSuffix(n.ID, "-VAULTB") && n.ID != "CAINSTANCE-VAULTB" {
			t.Errorf("node %s does not carry the new tag", n.ID)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	if _, err := parseFlags([]string{"--version"}); !errors.Is(err, errVersion) {
		t.Fatalf("--version should return errVersion, got %v", err)
	}
	if toolVersion() == "" {
		t.Fatal("toolVersion is empty")
	}
}
