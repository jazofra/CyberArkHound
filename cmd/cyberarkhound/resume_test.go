package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/snapshot"
)

// multiSafePVWA is a fake PVWA with several safes ("Safe0", "Safe1", ...),
// each holding two accounts ("<i>_1", "<i>_2"). It counts requests per path
// and can fail or observe chosen requests.
type multiSafePVWA struct {
	*httptest.Server
	safes int

	mu   sync.Mutex
	hits map[string]int
	// failMembers lists safes whose member listing fails with HTTP 403.
	failMembers map[string]bool
	// onRequest, if set, runs before each API request is answered.
	onRequest func(path string)
}

func newMultiSafePVWA(t *testing.T, safes int) *multiSafePVWA {
	f := &multiSafePVWA{safes: safes, hits: map[string]int{}, failMembers: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *multiSafePVWA) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *multiSafePVWA) countPrefix(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for path, hits := range f.hits {
		if strings.HasPrefix(path, prefix) {
			n += hits
		}
	}
	return n
}

func (f *multiSafePVWA) resetHits() {
	f.mu.Lock()
	f.hits = map[string]int{}
	f.mu.Unlock()
}

func (f *multiSafePVWA) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	write := func(body string) { _, _ = io.WriteString(w, body) }
	path := r.URL.Path
	if path == "/PasswordVault/API/Accounts" {
		path += "?" + r.URL.Query().Get("filter")
	}

	f.mu.Lock()
	f.hits[path]++
	hook := f.onRequest
	failMembers := f.failMembers
	f.mu.Unlock()

	switch path {
	case "/PasswordVault/API/Auth/CyberArk/Logon":
		write(`"session-token"`)
		return
	case "/PasswordVault/API/Auth/Logoff":
		write(`{}`)
		return
	}
	if hook != nil {
		hook(path)
	}

	switch {
	case path == "/PasswordVault/API/Users":
		write(`{"Users":[{"id":1,"username":"alice"},{"id":2,"username":"bob"}]}`)
	case path == "/PasswordVault/API/UserGroups":
		write(`{"value":[{"id":10,"groupName":"Ops"}]}`)
	case path == "/PasswordVault/API/UserGroups/10":
		write(`{"id":10,"groupName":"Ops","members":[{"username":"alice"},{"username":"bob"}]}`)
	case path == "/PasswordVault/API/safes":
		var safes []string
		for i := 0; i < f.safes; i++ {
			safes = append(safes, fmt.Sprintf(`{"safeName":"Safe%d","safeUrlId":"Safe%d"}`, i, i))
		}
		write(`{"value":[` + strings.Join(safes, ",") + `]}`)
	case strings.HasSuffix(path, "/Members"):
		safe := strings.TrimSuffix(strings.TrimPrefix(path, "/PasswordVault/API/Safes/"), "/Members")
		if failMembers[safe] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		write(fmt.Sprintf(`{"value":[
			{"memberName":"Ops","memberType":"Group","safeName":%q,"permissions":{"useAccounts":true,"retrieveAccounts":true}},
			{"memberName":"bob","memberType":"User","safeName":%q,"permissions":{"listAccounts":true,"manageSafeMembers":true}}]}`, safe, safe))
	case strings.HasPrefix(path, "/PasswordVault/API/Accounts?safeName eq Safe"):
		i := strings.TrimPrefix(path, "/PasswordVault/API/Accounts?safeName eq Safe")
		write(fmt.Sprintf(`{"value":[{"id":"%s_1"},{"id":"%s_2"}],"count":2}`, i, i))
	case strings.HasSuffix(path, "/Activities"):
		write(`{"Activities":[{"User":"alice","Action":"Retrieve password","Date":4102444800}]}`)
	case strings.HasPrefix(path, "/PasswordVault/API/Accounts/"):
		id := strings.TrimPrefix(path, "/PasswordVault/API/Accounts/")
		i, _, _ := strings.Cut(id, "_")
		write(fmt.Sprintf(`{"id":%q,"userName":"svc%s","address":"srv%s.corp.local","safeName":"Safe%s","platformId":"WinServer"}`, id, id, i, i))
	case path == "/PasswordVault/API/Platforms/":
		write(`{"Platforms":[{"general":{"id":"WinServer","name":"WinServer"}}]}`)
	case path == "/PasswordVault/API/Platforms/Targets/WinServer/PrivilegedSessionManagement":
		write(`{"PSMConnectors":[]}`)
	case path == "/PasswordVault/API/Platforms/Targets":
		write(`{"Platforms":[]}`)
	case path == "/PasswordVault/API/PSM/Servers/":
		write(`{"PSMServers":[]}`)
	case path == "/PasswordVault/API/PSM/Connectors/":
		write(`{"PSMConnectors":[]}`)
	case path == "/PasswordVault/WebServices/PIMServices.svc/Applications/":
		write(`{"application":[]}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func multiArgs(f *multiSafePVWA, out string, extra ...string) []string {
	return append([]string{
		"--pvwa", f.URL, "--username", "collector", "--password", "secret",
		"--output", out, "--target-domains", "corp.local", "--workers", "2",
	}, extra...)
}

func resumeArgs(raw, out string, extra ...string) []string {
	return append([]string{
		"--resume", raw, "--username", "collector", "--password", "secret",
		"--output", out, "--target-domains", "corp.local", "--workers", "2",
	}, extra...)
}

// cleanExport collects the fake environment in one uninterrupted run.
func cleanExport(t *testing.T, safes int, extra ...string) []byte {
	t.Helper()
	f := newMultiSafePVWA(t, safes)
	out := filepath.Join(t.TempDir(), "clean.json")
	if code := run(context.Background(), mustParse(t, multiArgs(f, out, extra...)...), quietLogger()); code != exitOK {
		t.Fatalf("clean run exit code = %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadProgress(t *testing.T, path string) *snapshot.Snapshot {
	t.Helper()
	snap, err := snapshot.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if snap.Progress == nil {
		t.Fatalf("%s has no progress record", path)
	}
	return snap
}

func TestResumeAfterInterruptionInAccountDetails(t *testing.T) {
	const safes = 4
	want := cleanExport(t, safes)

	f := newMultiSafePVWA(t, safes)
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var details atomic.Int32
	f.onRequest = func(path string) {
		if strings.HasPrefix(path, "/PasswordVault/API/Accounts/") && !strings.HasSuffix(path, "/Activities") {
			if details.Add(1) == 3 {
				cancel()
			}
		}
	}

	cfg := mustParse(t, multiArgs(f, filepath.Join(dir, "partial.json"), "--save-raw", raw)...)
	if code := run(ctx, cfg, quietLogger()); code != exitInterrupted {
		t.Fatalf("interrupted run exit code = %d, want %d", code, exitInterrupted)
	}
	partial := loadProgress(t, raw)
	doneBefore := len(partial.Progress.DetailedAccounts)
	if doneBefore == 0 || doneBefore >= 2*safes {
		t.Fatalf("expected a partly detailed collection, got %d of %d accounts detailed", doneBefore, 2*safes)
	}
	if !strings.Contains(strings.Join(partial.Incomplete, "\n"), "interrupted") {
		t.Errorf("saved progress should say the collection was interrupted: %v", partial.Incomplete)
	}

	f.mu.Lock()
	f.onRequest = nil
	f.mu.Unlock()
	f.resetHits()

	out := filepath.Join(dir, "resumed.json")
	if code := run(context.Background(), mustParse(t, resumeArgs(raw, out)...), quietLogger()); code != exitOK {
		t.Fatalf("resumed run exit code = %d", code)
	}

	// Finished stages and items are not fetched again.
	for _, path := range []string{"/PasswordVault/API/Users", "/PasswordVault/API/UserGroups", "/PasswordVault/API/safes", "/PasswordVault/API/Platforms/"} {
		if n := f.count(path); n != 0 {
			t.Errorf("%s was requested %d times by the resumed run", path, n)
		}
	}
	if n := f.countPrefix("/PasswordVault/API/Safes/"); n != 0 {
		t.Errorf("safe members were requested %d times although every safe was already scanned", n)
	}
	detailed := 0
	for i := 0; i < safes; i++ {
		for j := 1; j <= 2; j++ {
			detailed += f.count(fmt.Sprintf("/PasswordVault/API/Accounts/%d_%d", i, j))
		}
	}
	if want := 2*safes - doneBefore; detailed != want {
		t.Errorf("resumed run fetched %d account details, want %d", detailed, want)
	}

	got, _ := os.ReadFile(out)
	if string(got) != string(want) {
		t.Error("resumed export differs from an uninterrupted collection of the same environment")
	}
	final := loadProgress(t, raw)
	if len(final.Incomplete) != 0 {
		t.Errorf("finished collection should not be incomplete: %v", final.Incomplete)
	}
	if len(final.Progress.ResumedAt) != 1 {
		t.Errorf("ResumedAt = %v, want one entry", final.Progress.ResumedAt)
	}
}

func TestResumeAfterInterruptionInSafeScanKeepsOriginalOptions(t *testing.T) {
	want := cleanExport(t, 5, "--limit-safes", "3")

	f := newMultiSafePVWA(t, 5)
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var scans atomic.Int32
	f.onRequest = func(path string) {
		if strings.HasSuffix(path, "/Members") {
			if scans.Add(1) == 2 {
				cancel()
			}
		}
	}

	cfg := mustParse(t, multiArgs(f, filepath.Join(dir, "partial.json"), "--save-raw", raw, "--limit-safes", "3", "--workers", "1")...)
	if code := run(ctx, cfg, quietLogger()); code != exitInterrupted {
		t.Fatalf("interrupted run exit code = %d", code)
	}
	scanned := loadProgress(t, raw).Progress.ScannedSafes
	if len(scanned) == 0 || len(scanned) >= 3 {
		t.Fatalf("expected a partly scanned collection, got %v", scanned)
	}

	f.mu.Lock()
	f.onRequest = nil
	f.mu.Unlock()
	f.resetHits()

	// No --limit-safes: the resumed collection keeps the original limit.
	out := filepath.Join(dir, "resumed.json")
	if code := run(context.Background(), mustParse(t, resumeArgs(raw, out)...), quietLogger()); code != exitOK {
		t.Fatalf("resumed run exit code = %d", code)
	}
	for _, safe := range scanned {
		if n := f.count("/PasswordVault/API/Safes/" + safe + "/Members"); n != 0 {
			t.Errorf("already scanned %s was listed again", safe)
		}
	}
	got, _ := os.ReadFile(out)
	if string(got) != string(want) {
		t.Error("resumed export differs from an uninterrupted collection with the same options")
	}
}

func TestResumeRetriesFailedSafe(t *testing.T) {
	const safes = 3
	want := cleanExport(t, safes)

	f := newMultiSafePVWA(t, safes)
	f.failMembers["Safe1"] = true
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	cfg := mustParse(t, multiArgs(f, filepath.Join(dir, "first.json"), "--save-raw", raw)...)
	if code := run(context.Background(), cfg, quietLogger()); code != exitOK {
		t.Fatalf("first run exit code = %d", code)
	}
	first := loadProgress(t, raw)
	if !strings.Contains(strings.Join(first.Incomplete, "\n"), "members could not be fetched for 1 of 3 safes") {
		t.Fatalf("first run should report the failed safe: %v", first.Incomplete)
	}

	f.mu.Lock()
	f.failMembers = map[string]bool{}
	f.mu.Unlock()
	f.resetHits()

	out := filepath.Join(dir, "resumed.json")
	if code := run(context.Background(), mustParse(t, resumeArgs(raw, out)...), quietLogger()); code != exitOK {
		t.Fatalf("resumed run exit code = %d", code)
	}
	if n := f.countPrefix("/PasswordVault/API/Safes/"); n != 1 || f.count("/PasswordVault/API/Safes/Safe1/Members") != 1 {
		t.Errorf("resumed run should list only Safe1's members, made %d member requests", n)
	}
	// Safe1's accounts were listed and detailed by the first run.
	if n := f.countPrefix("/PasswordVault/API/Accounts/"); n != 0 {
		t.Errorf("resumed run fetched %d account details or activities; none were missing", n)
	}
	got, _ := os.ReadFile(out)
	if string(got) != string(want) {
		t.Error("export after retrying the failed safe differs from a clean collection")
	}
	if final := loadProgress(t, raw); len(final.Incomplete) != 0 {
		t.Errorf("collection should be complete after the retry: %v", final.Incomplete)
	}
}

func TestProgressIsSavedWhileCollecting(t *testing.T) {
	f := newMultiSafePVWA(t, 3)
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")

	// Simulate a crash: look at the file the way a later --resume would,
	// in the middle of the account-details stage.
	var seenMu sync.Mutex
	var seen *snapshot.Snapshot
	var details atomic.Int32
	f.onRequest = func(path string) {
		if strings.HasPrefix(path, "/PasswordVault/API/Accounts/") && !strings.HasSuffix(path, "/Activities") {
			if details.Add(1) == 4 {
				snap, _ := snapshot.Load(raw)
				seenMu.Lock()
				seen = snap
				seenMu.Unlock()
			}
		}
	}
	cfg := mustParse(t, multiArgs(f, filepath.Join(dir, "out.json"), "--save-raw", raw, "--workers", "1")...)
	cfg.checkpointInterval = time.Nanosecond
	if code := run(context.Background(), cfg, quietLogger()); code != exitOK {
		t.Fatalf("exit code = %d", code)
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if seen == nil || seen.Progress == nil {
		t.Fatal("no progress had been saved by the middle of the collection")
	}
	if len(seen.Progress.ScannedSafes) != 3 || len(seen.Progress.DetailedAccounts) < 2 {
		t.Errorf("mid-run progress: %d safes scanned, %d accounts detailed", len(seen.Progress.ScannedSafes), len(seen.Progress.DetailedAccounts))
	}
	if !strings.Contains(strings.Join(seen.Incomplete, "\n"), "--resume") {
		t.Errorf("a mid-run file must say it is unfinished and how to continue: %v", seen.Incomplete)
	}
}

func TestResumeRejectsOtherPVWA(t *testing.T) {
	f := newMultiSafePVWA(t, 1)
	dir := t.TempDir()
	raw := filepath.Join(dir, "raw.json")
	if code := run(context.Background(), mustParse(t, multiArgs(f, filepath.Join(dir, "a.json"), "--save-raw", raw)...), quietLogger()); code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	cfg := mustParse(t, append(resumeArgs(raw, filepath.Join(dir, "b.json")), "--pvwa", "https://other.example.com")...)
	if code := run(context.Background(), cfg, quietLogger()); code != exitError {
		t.Fatalf("resuming against another PVWA: exit code = %d, want %d", code, exitError)
	}
	if _, err := parseFlags([]string{"--resume", raw, "--from-raw", raw, "--output", "o", "--target-domains", "d"}); err == nil {
		t.Error("--resume with --from-raw should be rejected")
	}
}
