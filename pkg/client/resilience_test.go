package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentReauthIsRaceFree reproduces a PVWA session expiring while many
// workers are mid-request: one worker re-authenticates while the others keep
// reading the token. Run under -race, this failed before the token was guarded.
func TestConcurrentReauthIsRaceFree(t *testing.T) {
	var logons, reqs atomic.Int32
	var mu sync.Mutex
	valid := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/PasswordVault/API/Auth/CyberArk/Logon" {
			tok := fmt.Sprintf("tok%d", logons.Add(1))
			mu.Lock()
			valid = tok
			mu.Unlock()
			_, _ = io.WriteString(w, `"`+tok+`"`)
			return
		}
		// Expire the session every 40 requests.
		if reqs.Add(1)%40 == 0 {
			mu.Lock()
			valid = "expired"
			mu.Unlock()
		}
		mu.Lock()
		ok := r.Header.Get("Authorization") == valid
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.MaxReauthAttempts = 1000
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				resp, err := client.requestWithRetries("GET", server.URL+"/x", nil, 0, 3)
				if err != nil {
					failures.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d requests failed despite re-authentication", n)
	}
	if logons.Load() < 2 {
		t.Fatalf("expected at least one re-authentication, got %d logons", logons.Load())
	}
}

func TestRateLimitRetriesAreCapped(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.MaxRateLimitRetries = 3
	_, err := client.requestWithRetries("GET", server.URL+"/x", nil, time.Second, 3)
	if err == nil {
		t.Fatal("expected an error after repeated HTTP 429")
	}
	if httpStatus(err) != http.StatusTooManyRequests {
		t.Fatalf("error should carry HTTP 429, got %v", err)
	}
	if got := hits.Load(); got != 4 {
		t.Fatalf("server saw %d requests, want 4 (1 + 3 retries)", got)
	}
}

func TestRateLimitHonoursRetryAfter(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client := testClient(server.URL)
	// Without Retry-After the client would back off for 30s.
	client.RetryInitialBackoff = 30 * time.Second
	client.RetryMaxBackoff = 30 * time.Second

	start := time.Now()
	resp, err := client.requestWithRetries("GET", server.URL+"/x", nil, time.Second, 3)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("request took %s; Retry-After: 0 should have been honoured", elapsed)
	}
}

func TestRetryAfterDelay(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		header string
		want   time.Duration
		ok     bool
	}{
		{"", 0, false},
		{"7", 7 * time.Second, true},
		{" 0 ", 0, true},
		{"-3", 0, false},
		{"soon", 0, false},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
	}
	for _, tt := range tests {
		got, ok := retryAfterDelay(tt.header, now)
		if got != tt.want || ok != tt.ok {
			t.Errorf("retryAfterDelay(%q) = (%s, %v), want (%s, %v)", tt.header, got, ok, tt.want, tt.ok)
		}
	}
}

func TestCancelledContextAbortsRetryWait(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.RetryInitialBackoff = 30 * time.Second
	client.RetryMaxBackoff = 30 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	client.SetContext(ctx)
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := client.requestWithRetries("GET", server.URL+"/x", nil, time.Second, 5)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %s; the retry wait should have been interrupted", elapsed)
	}
}

func TestLogoffWorksAfterCancellation(t *testing.T) {
	var loggedOff atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/PasswordVault/API/Auth/Logoff" {
			loggedOff.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.Token = "session"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client.SetContext(ctx)

	if err := client.Logoff(); err != nil {
		t.Fatalf("Logoff after cancellation: %v", err)
	}
	if !loggedOff.Load() {
		t.Fatal("logoff request was not sent")
	}
}

func TestListSafeMembersRequestsPredefinedMembers(t *testing.T) {
	var gotFilter string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("filter")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"value": []map[string]interface{}{{"memberName": "Vault Admins", "memberType": "Group", "safeName": "S1"}},
		})
	}))
	defer server.Close()

	client := testClient(server.URL)
	members, err := client.ListSafeMembers("S1", "S1")
	if err != nil {
		t.Fatalf("ListSafeMembers: %v", err)
	}
	if gotFilter != "includePredefinedUsers eq true" {
		t.Fatalf("filter = %q, want includePredefinedUsers eq true", gotFilter)
	}
	if len(members) != 1 || members[0].MemberName != "Vault Admins" {
		t.Fatalf("unexpected members: %+v", members)
	}
	if reasons := client.IncompleteReasons(); len(reasons) != 0 {
		t.Fatalf("no gap expected, got %v", reasons)
	}
}

func TestListSafeMembersFallsBackWhenFilterRejected(t *testing.T) {
	var filtered, plain atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") != "" {
			filtered.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"ErrorMessage":"unknown filter"}`)
			return
		}
		plain.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"value":[{"memberName":"alice","memberType":"User"}]}`)
	}))
	defer server.Close()

	client := testClient(server.URL)
	for _, safe := range []string{"S1", "S2", "S3"} {
		members, err := client.ListSafeMembers(safe, "")
		if err != nil {
			t.Fatalf("ListSafeMembers(%s): %v", safe, err)
		}
		if len(members) != 1 {
			t.Fatalf("ListSafeMembers(%s) returned %d members, want 1", safe, len(members))
		}
	}
	if filtered.Load() != 1 {
		t.Fatalf("filtered requests = %d, want 1 (filter dropped after first rejection)", filtered.Load())
	}
	if plain.Load() != 3 {
		t.Fatalf("plain requests = %d, want 3", plain.Load())
	}
	reasons := client.IncompleteReasons()
	if len(reasons) != 1 || !strings.Contains(reasons[0], "built-in safe members") {
		t.Fatalf("expected one built-in-members gap, got %v", reasons)
	}
}

func TestListSafeMembersKeepsFilterWhenSafeItselfFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := testClient(server.URL)
	if _, err := client.ListSafeMembers("Broken", ""); err == nil {
		t.Fatal("expected an error")
	}
	if client.predefinedFilterRejected.Load() {
		t.Fatal("filter must not be dropped when the plain request fails too")
	}
}

func TestListGroupsRecordsFailedDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/PasswordVault/API/UserGroups":
			_, _ = io.WriteString(w, `{"value":[{"id":1,"groupName":"Good"},{"id":2,"groupName":"Bad"}]}`)
		case "/PasswordVault/API/UserGroups/1":
			_, _ = io.WriteString(w, `{"id":1,"groupName":"Good","members":[{"username":"alice"}]}`)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	groups, err := client.ListGroups(nil, 2)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 2 || len(groups[0].Members) != 1 {
		t.Fatalf("unexpected groups: %+v", groups)
	}
	reasons := client.IncompleteReasons()
	if len(reasons) != 1 || !strings.Contains(reasons[0], "1 of 2 groups") {
		t.Fatalf("expected one group gap, got %v", reasons)
	}
}

func TestListApplicationsWithAuthMarksUnreadableAuthentications(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/Applications/") {
			_, _ = io.WriteString(w, `{"application":[{"AppID":"App1"}]}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := testClient(server.URL)
	apps, err := client.ListApplicationsWithAuth(2)
	if err != nil {
		t.Fatalf("ListApplicationsWithAuth: %v", err)
	}
	if len(apps) != 1 || !apps[0].AuthenticationsUnknown {
		t.Fatalf("App1 should be marked AuthenticationsUnknown: %+v", apps)
	}
	if len(client.IncompleteReasons()) != 1 {
		t.Fatalf("expected one recorded gap, got %v", client.IncompleteReasons())
	}
}

func TestSafePathSegment(t *testing.T) {
	tests := []struct {
		name, urlID, want string
	}{
		{"Prod", "Prod", "Prod"},
		{"My Safe", "My%20Safe", "My%20Safe"},
		// PVWA's own encoding of '&' is kept; url.PathEscape would leave it raw.
		{"R&D", "R%26D", "R%26D"},
		// No safeUrlId (older PVWA): escape the name.
		{"My Safe", "", "My%20Safe"},
		{"R&D", "", "R&D"},
		// Not a valid escaped segment: fall back to escaping the name.
		{"My Safe", "My Safe", "My%20Safe"},
		{"Bad", "100%", "Bad"},
		{"Bad", "a/b", "Bad"},
	}
	for _, tt := range tests {
		if got := safePathSegment(tt.name, tt.urlID); got != tt.want {
			t.Errorf("safePathSegment(%q, %q) = %q, want %q", tt.name, tt.urlID, got, tt.want)
		}
	}
}

func TestListSafeMembersUsesSafeURLIDVerbatim(t *testing.T) {
	var gotURI string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"value":[]}`)
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.IncludePredefinedSafeMembers = false
	if _, err := client.ListSafeMembers("R&D", "R%26D"); err != nil {
		t.Fatalf("ListSafeMembers: %v", err)
	}
	if !strings.HasPrefix(gotURI, "/PasswordVault/API/Safes/R%26D/Members?") {
		t.Fatalf("request URI = %q, want the safeUrlId sent verbatim", gotURI)
	}
}
