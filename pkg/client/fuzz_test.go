package client

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func FuzzNormalizeBaseURL(f *testing.F) {
	for _, seed := range []string{"", "pvwa.example.com", " https://pvwa.example.com/// ", "http://x", "://", "/", "h:/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := NormalizeBaseURL(raw)
		if strings.TrimSpace(raw) == "" {
			if got != "" {
				t.Errorf("NormalizeBaseURL(%q) = %q, want empty", raw, got)
			}
			return
		}
		if strings.HasSuffix(got, "/") {
			t.Errorf("NormalizeBaseURL(%q) = %q ends in a slash", raw, got)
		}
		// A well-formed address keeps its host, with https assumed.
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
			n, err := url.Parse(got)
			if err != nil || n.Host != u.Host || n.Scheme != u.Scheme {
				t.Errorf("NormalizeBaseURL(%q) = %q changed the scheme or host", raw, got)
			}
		}
	})
}

// A safe's path segment is built from data PVWA returned. Whatever that data
// is, it must stay one path segment: it may not add segments, a query or a
// fragment to the request URL.
func FuzzSafePathSegment(f *testing.F) {
	f.Add("Prod", "Prod")
	f.Add("R&D Safe", "R%26D%20Safe")
	f.Add("a/b", "a/b")
	f.Add("x?y#z", "x?y#z")
	f.Add("100%", "100%")
	f.Add("..", "..")
	f.Add("", "%zz")
	f.Fuzz(func(t *testing.T, name, urlID string) {
		segment := safePathSegment(name, urlID)
		if strings.ContainsAny(segment, "/?#") {
			t.Fatalf("safePathSegment(%q, %q) = %q breaks out of its path segment", name, urlID, segment)
		}
		u, err := url.Parse("https://pvwa.example/PasswordVault/API/Safes/" + segment + "/Members")
		if err != nil {
			t.Fatalf("safePathSegment(%q, %q) = %q does not form a URL: %v", name, urlID, segment, err)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("safePathSegment(%q, %q) = %q adds a query or fragment", name, urlID, segment)
		}
		if parts := strings.Split(u.EscapedPath(), "/"); len(parts) != 6 || parts[5] != "Members" {
			t.Errorf("safePathSegment(%q, %q) = %q changes the path to %q", name, urlID, segment, u.EscapedPath())
		}
	})
}

func FuzzRetryAfterDelay(f *testing.F) {
	for _, seed := range []string{"", "0", "120", "-5", "Wed, 21 Oct 2015 07:28:00 GMT", "99999999999999999999", "9227000000", " 3 ", "soon"} {
		f.Add(seed)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, header string) {
		delay, ok := retryAfterDelay(header, now)
		if delay < 0 {
			t.Errorf("retryAfterDelay(%q) = %s, want a non-negative delay", header, delay)
		}
		if !ok && delay != 0 {
			t.Errorf("retryAfterDelay(%q) = %s without a usable value", header, delay)
		}
	})
}
