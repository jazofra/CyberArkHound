package graph

import (
	"regexp"
	"strings"
	"testing"
)

var (
	tagPattern  = regexp.MustCompile(`^[A-Z0-9]{1,4}$`)
	permPattern = regexp.MustCompile(`^[a-z0-9]*$`)
)

// The tag becomes part of every node ID, so whatever the --pvwa argument
// looks like it must stay short and limited to characters safe in an ID.
func FuzzPVWATagFromArg(f *testing.F) {
	for _, seed := range []string{"", "pvwa.example.com", "https://cyberark.acme-corp.example.com/PasswordVault", "10.0.0.1", "[::1]:8443", "http://", "pv_wa.a-b_c.d", "ünï.çødé.com", "a", "://x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, arg string) {
		tag := PVWATagFromArg(arg)
		if !tagPattern.MatchString(tag) {
			t.Errorf("PVWATagFromArg(%q) = %q, want 1-4 upper-case letters or digits", arg, tag)
		}
		if again := PVWATagFromArg(arg); again != tag {
			t.Errorf("PVWATagFromArg(%q) is not deterministic: %q then %q", arg, tag, again)
		}
	})
}

func FuzzParseDN(f *testing.F) {
	for _, seed := range []string{"", "CN=Ortiz Jon z0052twm,OU=Users,DC=corp,DC=local", "cn=a,dc=B", "DC=", ",,,", "CN=x\\,y,DC=corp", "CN=,DC=,DC=", "CN=user@corp,DC=corp"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, dn string) {
		domain := ParseDomainFromDN(dn)
		if domain != strings.ToLower(domain) {
			t.Errorf("ParseDomainFromDN(%q) = %q, want lower case", dn, domain)
		}
		if strings.Contains(domain, ",") {
			t.Errorf("ParseDomainFromDN(%q) = %q contains a comma", dn, domain)
		}
		if sam := ParseSAMAccountNameFromDN(dn); sam != "" && !samAccountNameRe.MatchString(sam) {
			t.Errorf("ParseSAMAccountNameFromDN(%q) = %q is not a plausible account name", dn, sam)
		}
	})
}

func FuzzNormPermName(f *testing.F) {
	for _, seed := range []string{"", "useAccounts", "Requests Authorization Level 1", "MANAGE_SAFE", "ünï"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		norm := NormPermName(name)
		if !permPattern.MatchString(norm) {
			t.Errorf("NormPermName(%q) = %q", name, norm)
		}
		if NormPermName(norm) != norm {
			t.Errorf("NormPermName is not idempotent for %q", name)
		}
	})
}

func FuzzAccountNamesAndDomains(f *testing.F) {
	f.Add("CORP\\jdoe", "srv01.emea.corp.local", "corp.local,emea.corp.local")
	f.Add("jdoe@corp.local", "CORP.LOCAL.", " corp.local. ")
	f.Add("@", ".", ",")
	f.Fuzz(func(t *testing.T, user, address, domains string) {
		name := adAccountName(user)
		if strings.Contains(name, "\\") {
			t.Errorf("adAccountName(%q) = %q still has a domain prefix", user, name)
		}
		targets := NormalizeDomains(strings.Split(domains, ","))
		addr := strings.TrimRight(strings.ToLower(strings.TrimSpace(address)), ".")
		domain, isDomain := matchTargetDomain(addr, targets)
		if domain == "" {
			if isDomain {
				t.Errorf("matchTargetDomain(%q, %q) reports a domain without naming it", addr, targets)
			}
			return
		}
		lower := strings.ToLower(domain)
		if isDomain && lower != addr {
			t.Errorf("matchTargetDomain(%q, %q) = %q as the domain itself", addr, targets, domain)
		}
		if !isDomain && !strings.HasSuffix(addr, "."+lower) {
			t.Errorf("matchTargetDomain(%q, %q) = %q, which the address is not in", addr, targets, domain)
		}
	})
}
