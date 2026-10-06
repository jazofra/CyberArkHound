package graph

import "testing"

// TestPVWATagFromArg pins the derivation: the tag namespaces every node ID,
// so changing it changes the identity of every object in an existing import.
func TestPVWATagFromArg(t *testing.T) {
	tests := map[string]string{
		// Documented examples.
		"pvwa.example.com":               "PVEX",
		"cyberark.acme-corp.example.com": "CYAC",
		// Scheme, port, path and case do not matter.
		"https://pvwa.example.com":                     "PVEX",
		"https://PVWA.Example.com:8443/PasswordVault/": "PVEX",
		"http://pvwa.example.com":                      "PVEX",
		// Privilege Cloud subdomains.
		"https://abc123.privilegecloud.cyberark.cloud": "ABPR",
		// Short or single-label hosts are padded deterministically.
		"pv.a.com": "PVAA",
		"pvwa":     "PVWA",
		"x":        "XXXX",
		// Known collisions: only the first two labels count, so different
		// hosts can share a tag (see --pvwa-tag).
		"pvwa.example.org": "PVEX",
		"10.0.0.5":         "1000",
		"10.0.0.6":         "1000",
		"":                 "PVWA",
	}
	for arg, want := range tests {
		if got := PVWATagFromArg(arg); got != want {
			t.Errorf("PVWATagFromArg(%q) = %q, want %q", arg, got, want)
		}
	}
}
