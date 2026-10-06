package graph

import (
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
)

func TestReferencedButUncollectedObjectsGetTypedPlaceholders(t *testing.T) {
	og, err := BuildOpenGraph(BuildInput{
		Users:  []models.User{{Username: "alice", GroupsMembership: []models.UserGroupMembership{{GroupName: "Ghost Group"}}}},
		Groups: []models.Group{{ID: 1, GroupName: "Ops", Members: []models.GroupMember{{Username: "Departed.User"}}}},
		Safes:  []models.Safe{{SafeName: "Prod", Creator: models.SafeCreator{Name: "OldAdmin"}, ManagingCPM: "PasswordManager"}},
		SafeMembers: []models.SafeMember{
			{MemberName: "Vault Admins", MemberType: "Group", SafeName: "Prod", Permissions: map[string]interface{}{"manageSafeMembers": true}},
		},
		Accounts: []models.Account{{ID: "1_1", UserName: "svc", SafeName: "Prod"}},
		LinkedAccounts: map[string][]models.LinkedAccount{
			"1_1": {{AccountID: "9_9", Name: "Operating System-WinDomain-corp-reconcile", SafeName: "HiddenSafe", ExtraPassID: 3}},
		},
		AccountActivities: map[string][]models.AccountActivity{
			"1_1": {{User: "ex-employee", Action: "Retrieve password", Date: float64(1700000000)}},
		},
		PVWATag: "PVWA",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct{ kind, name string }{
		"CAGROUP-GHOST GROUP-PVWA":    {"CyberArk_Group", "Ghost Group"},
		"CAUSER-DEPARTED.USER-PVWA":   {"CyberArk_User", "Departed.User"},
		"CAUSER-OLDADMIN-PVWA":        {"CyberArk_User", "OldAdmin"},
		"CAUSER-PASSWORDMANAGER-PVWA": {"CyberArk_User", "PasswordManager"},
		"CAGROUP-VAULT ADMINS-PVWA":   {"CyberArk_Group", "Vault Admins"},
		"CAACCOUNT-9_9-PVWA":          {"CyberArk_Account", "Operating System-WinDomain-corp-reconcile"},
		"CAUSER-EX-EMPLOYEE-PVWA":     {"CyberArk_User", "ex-employee"},
	}
	for id, w := range want {
		n := og.Nodes[id]
		if n == nil {
			t.Errorf("no placeholder node %s", id)
			continue
		}
		if len(n.Kinds) != 2 || n.Kinds[0] != w.kind || n.Kinds[1] != "CyberArkBase" {
			t.Errorf("%s kinds = %v, want [%s CyberArkBase]", id, n.Kinds, w.kind)
		}
		if n.Properties["name"] != w.name || n.Properties["placeholder"] != true {
			t.Errorf("%s properties = %v, want name %q and placeholder=true", id, n.Properties, w.name)
		}
	}

	// Collected objects are never marked as placeholders.
	for _, id := range []string{"CAUSER-ALICE-PVWA", "CAGROUP-OPS-PVWA", "CASAFE-PROD-PVWA", "CAACCOUNT-1_1-PVWA"} {
		if n := og.Nodes[id]; n == nil || n.Properties["placeholder"] != nil {
			t.Errorf("%s should be a collected node without placeholder, got %+v", id, n)
		}
	}

	// Every edge endpoint matched by ID now has a node.
	for _, edges := range [][]*Edge{og.InternalEdges, og.ExternalEdges} {
		for _, e := range edges {
			for _, end := range []EdgeRef{e.Start, e.End} {
				if end.MatchBy == "id" && og.Nodes[end.Value] == nil {
					t.Errorf("%s edge endpoint %s has no node", e.Kind, end.Value)
				}
			}
		}
	}
}

func TestPlaceholderSafesDoNotCountAsUnmanaged(t *testing.T) {
	og, err := BuildOpenGraph(BuildInput{
		// The account's safe was not collected, so it becomes a placeholder
		// with no managingCPM; that must not be reported as a finding.
		Accounts: []models.Account{{ID: "1_1", SafeName: "UnlistedSafe"}},
		PVWATag:  "PVWA",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if n := og.Nodes["CASAFE-UNLISTEDSAFE-PVWA"]; n == nil || n.Properties["placeholder"] != true {
		t.Fatalf("expected a placeholder safe, got %+v", n)
	}
	for _, f := range ComputeFindings(og) {
		if f.ID == "SAFE_NO_CPM" {
			t.Errorf("placeholder safe reported as SAFE_NO_CPM: %+v", f)
		}
	}
}

func TestNodeRefFromID(t *testing.T) {
	for id, want := range map[string]nodeRef{
		"CAUSER-JDOE-PVWA":       {"CyberArk_User", "JDOE"},
		"CAPSMSERVER-PSM01-PVWA": {"CyberArk_PSMServer", "PSM01"},
		"CAACCOUNT-1_2-PVWA":     {"CyberArk_Account", "1_2"},
		"SOMETHING-ELSE":         {"CyberArkBase", "SOMETHING-ELSE"},
	} {
		if got := nodeRefFromID(id, "pvwa"); got != want {
			t.Errorf("nodeRefFromID(%q) = %+v, want %+v", id, got, want)
		}
	}
}
