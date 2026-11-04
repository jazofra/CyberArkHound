package graph

import (
	"strings"
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
)

// externalEdge returns the single external edge of kind starting at start,
// failing the test if there is not exactly one.
func externalEdge(t *testing.T, og *OpenGraph, kind, start string) *Edge {
	t.Helper()
	var found []*Edge
	for _, e := range og.ExternalEdges {
		if e.Kind == kind && e.Start.Value == start {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected one %s edge from %s, got %d: %+v", kind, start, len(found), found)
	}
	return found[0]
}

func noExternalEdges(t *testing.T, og *OpenGraph, kind string) {
	t.Helper()
	if edges := externalEdgesByKind(og, kind); len(edges) != 0 {
		t.Fatalf("expected no %s edges, got %+v", kind, edges)
	}
}

func buildUsers(t *testing.T, parseSAM bool, users ...models.User) *OpenGraph {
	t.Helper()
	og, err := BuildOpenGraph(BuildInput{Users: users, PVWATag: "PVWA", ParseSAMAccountNameFromDN: parseSAM}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	return og
}

func syncsToUserFrom(t *testing.T, og *OpenGraph, caUserID string) *Edge {
	t.Helper()
	var found []*Edge
	for _, e := range externalEdgesByKind(og, "CyberArk_SyncsToUser") {
		if e.End.Value == caUserID {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected one CyberArk_SyncsToUser edge to %s, got %+v", caUserID, found)
	}
	return found[0]
}

func TestSyncsToUser(t *testing.T) {
	tests := []struct {
		name     string
		user     models.User
		parseSAM bool
		wantAD   string // "" means no edge
	}{
		{"LDAP user", models.User{Username: "jdoe", Source: "LDAP", UserDN: "CN=John Doe,OU=Users,DC=corp,DC=local"}, false, "JDOE@CORP.LOCAL"},
		{"lower-case DN", models.User{Username: "jdoe", Source: "LDAP", UserDN: "cn=John Doe,ou=Users,dc=corp,dc=local"}, false, "JDOE@CORP.LOCAL"},
		{"DN alone marks LDAP", models.User{Username: "jdoe", UserDN: "CN=John Doe,DC=corp,DC=local"}, false, "JDOE@CORP.LOCAL"},
		{"UPN username", models.User{Username: "jdoe@corp.local", Source: "LDAP", UserDN: "CN=John Doe,DC=corp,DC=local"}, false, "JDOE@CORP.LOCAL"},
		{"down-level username", models.User{Username: `CORP\jdoe`, Source: "LDAP", UserDN: "CN=John Doe,DC=corp,DC=local"}, false, "JDOE@CORP.LOCAL"},
		{"sAMAccountName from CN", models.User{Username: "John Doe", Source: "LDAP", UserDN: "CN=Doe John z0052twm,OU=Users,DC=corp,DC=local"}, true, "Z0052TWM@CORP.LOCAL"},
		{"sAMAccountName parsing off", models.User{Username: "jdoe", Source: "LDAP", UserDN: "CN=Doe John z0052twm,DC=corp,DC=local"}, false, "JDOE@CORP.LOCAL"},
		{"unparseable CN falls back", models.User{Username: "jdoe", Source: "LDAP", UserDN: `CN=Doe\, John,DC=corp,DC=local`}, true, "JDOE@CORP.LOCAL"},
		{"'DC=' inside another RDN value", models.User{Username: "jdoe", Source: "LDAP", UserDN: "CN=jdoe,OU=OLDDC=1,DC=corp,DC=local"}, false, "JDOE@CORP.LOCAL"},
		{"vault user", models.User{Username: "vaultadmin", Source: "CyberArk"}, false, ""},
		{"LDAP source without DN", models.User{Username: "jdoe", Source: "LDAP"}, false, ""},
		{"DN without domain components", models.User{Username: "jdoe", Source: "LDAP", UserDN: "CN=jdoe,OU=Users"}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			og := buildUsers(t, tt.parseSAM, tt.user)
			if tt.wantAD == "" {
				noExternalEdges(t, og, "CyberArk_SyncsToUser")
				return
			}
			caID := strings.ToUpper("causer-" + tt.user.Username + "-PVWA")
			e := syncsToUserFrom(t, og, caID)
			if e.Start.Value != tt.wantAD || e.Start.MatchBy != "name" || e.End.MatchBy != "id" {
				t.Errorf("edge = %s (%s) -> %s (%s), want %s (name) -> user (id)", e.Start.Value, e.Start.MatchBy, e.End.Value, e.End.MatchBy, tt.wantAD)
			}
			if e.Props["domain"] != "corp.local" {
				t.Errorf("domain = %v, want corp.local", e.Props["domain"])
			}
		})
	}
}

func TestSyncsToGroup(t *testing.T) {
	og, err := BuildOpenGraph(BuildInput{
		Groups: []models.Group{
			{ID: 1, GroupName: "Domain Admins", Directory: "corp.local", DN: "CN=Domain Admins,CN=Users,DC=corp,DC=local"},
			{ID: 2, GroupName: "VaultOnly"},
			{ID: 3, GroupName: "NoDN", Directory: "corp.local"},
		},
		PVWATag: "PVWA",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	edges := externalEdgesByKind(og, "CyberArk_SyncsToGroup")
	if len(edges) != 1 {
		t.Fatalf("expected one SyncsToGroup edge, got %+v", edges)
	}
	if e := edges[0]; e.Start.Value != "DOMAIN ADMINS@CORP.LOCAL" || e.End.Value != "CAGROUP-DOMAIN ADMINS-PVWA" {
		t.Errorf("edge = %s -> %s", e.Start.Value, e.End.Value)
	}
}

func TestAccountADLinks(t *testing.T) {
	tests := []struct {
		name     string
		account  models.Account
		domains  []string
		wantKind string // "" means no edge
		wantEnd  string
		domain   string
	}{
		{"domain account", models.Account{UserName: "svc-backup", Address: "corp.local"}, []string{"corp.local"}, "CyberArk_SyncsToADUser", "SVC-BACKUP@CORP.LOCAL", "corp.local"},
		{"domain account, UPN username", models.Account{UserName: "svc-backup@corp.local", Address: "corp.local"}, []string{"corp.local"}, "CyberArk_SyncsToADUser", "SVC-BACKUP@CORP.LOCAL", "corp.local"},
		{"domain account, down-level username", models.Account{UserName: `CORP\svc-backup`, Address: "corp.local"}, []string{"corp.local"}, "CyberArk_SyncsToADUser", "SVC-BACKUP@CORP.LOCAL", "corp.local"},
		{"local account on member server", models.Account{UserName: "Administrator", Address: "srv01.corp.local"}, []string{"corp.local"}, "CyberArk_CanConnect", "SRV01.CORP.LOCAL", "corp.local"},
		{"host with trailing dot and case", models.Account{UserName: "admin", Address: " SRV01.Corp.Local. "}, []string{"corp.local"}, "CyberArk_CanConnect", "SRV01.CORP.LOCAL", "corp.local"},
		{"host in a child domain", models.Account{UserName: "admin", Address: "srv02.emea.corp.local"}, []string{"corp.local"}, "CyberArk_CanConnect", "SRV02.EMEA.CORP.LOCAL", "corp.local"},
		{"most specific target domain wins", models.Account{UserName: "admin", Address: "srv02.emea.corp.local"}, []string{"corp.local", "emea.corp.local"}, "CyberArk_CanConnect", "SRV02.EMEA.CORP.LOCAL", "emea.corp.local"},
		{"child domain itself", models.Account{UserName: "svc", Address: "emea.corp.local"}, []string{"corp.local", "emea.corp.local"}, "CyberArk_SyncsToADUser", "SVC@EMEA.CORP.LOCAL", "emea.corp.local"},
		{"other domain", models.Account{UserName: "admin", Address: "srv01.other.local"}, []string{"corp.local"}, "", "", ""},
		{"lookalike suffix", models.Account{UserName: "admin", Address: "srv01.notcorp.local"}, []string{"corp.local"}, "", "", ""},
		{"IP address", models.Account{UserName: "admin", Address: "10.0.0.5"}, []string{"corp.local"}, "", "", ""},
		{"short host name", models.Account{UserName: "admin", Address: "SRV01"}, []string{"corp.local"}, "", "", ""},
		{"no username", models.Account{Address: "corp.local"}, []string{"corp.local"}, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.account.ID = "1_1"
			tt.account.SafeName = "S"
			og := buildWithAccounts([]models.Account{tt.account}, tt.domains)
			if tt.wantKind == "" {
				if len(og.ExternalEdges) != 0 {
					t.Fatalf("expected no AD edges, got %+v", og.ExternalEdges)
				}
				return
			}
			e := externalEdge(t, og, tt.wantKind, "CAACCOUNT-1_1-PVWA")
			if e.End.Value != tt.wantEnd || e.End.MatchBy != "name" {
				t.Errorf("edge ends at %s (%s), want %s (name)", e.End.Value, e.End.MatchBy, tt.wantEnd)
			}
			if e.Props["domain"] != tt.domain {
				t.Errorf("domain = %v, want %s", e.Props["domain"], tt.domain)
			}
			if len(og.ExternalEdges) != 1 {
				t.Errorf("expected exactly one AD edge, got %+v", og.ExternalEdges)
			}
		})
	}
}

func TestParseDomainFromDN(t *testing.T) {
	for dn, want := range map[string]string{
		"CN=a,OU=b,DC=corp,DC=local":   "corp.local",
		"CN=a, DC=Corp, DC=Local":      "corp.local",
		"CN=a,OU=OLDDC=1,DC=corp,DC=x": "corp.x",
		"CN=a,OU=b":                    "",
		"":                             "",
	} {
		if got := ParseDomainFromDN(dn); got != want {
			t.Errorf("ParseDomainFromDN(%q) = %q, want %q", dn, got, want)
		}
	}
}
