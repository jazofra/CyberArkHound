package graph

import (
	"testing"

	"github.com/jazofra/CyberArkHound/pkg/models"
)

func findingObjectIDs(f *Finding) map[string]string {
	ids := make(map[string]string)
	if f != nil {
		for _, o := range f.Objects {
			ids[o.ID] = o.Target
		}
	}
	return ids
}

func edgesOfKind(og *OpenGraph, kind string) []*Edge {
	var out []*Edge
	for _, e := range og.InternalEdges {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// reviewVault is a vault with one dual-control platform and three safes:
// Approved has an approver, Unapproved has none, and Plain holds an account
// on a platform without dual control.
func reviewVault() BuildInput {
	dual := models.Platform{General: models.PlatformGeneral{ID: "Dual", Name: "Dual"}}
	dual.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval = true
	perms := func(names ...string) map[string]interface{} {
		m := make(map[string]interface{})
		for _, n := range names {
			m[n] = true
		}
		return m
	}
	return BuildInput{
		PVWATag: "TEST",
		Users: []models.User{
			{Username: "alice", Enabled: true},
			{Username: "bob", Enabled: true},
			{Username: "carol", Enabled: true},
			{Username: "dave", Enabled: false},
			{Username: "erin", Enabled: true, Suspended: true},
			{Username: "frank", Enabled: true},
			{Username: "idle", Enabled: false},
		},
		Platforms: []models.Platform{dual, {General: models.PlatformGeneral{ID: "Open", Name: "Open"}}},
		Safes: []models.Safe{
			{SafeName: "Approved", ManagingCPM: "PasswordManager"},
			{SafeName: "Unapproved", ManagingCPM: "PasswordManager"},
			{SafeName: "Plain", ManagingCPM: "PasswordManager"},
		},
		Accounts: []models.Account{
			{ID: "1", UserName: "a1", SafeName: "Approved", PlatformID: "Dual",
				SecretManagement: map[string]interface{}{"automaticManagementEnabled": true}},
			{ID: "2", UserName: "a2", SafeName: "Unapproved", PlatformID: "Dual",
				SecretManagement: map[string]interface{}{"automaticManagementEnabled": false}},
			// Listed under a different spelling of its safe's name.
			{ID: "3", UserName: "a3", SafeName: "PLAIN", PlatformID: "Open"},
		},
		SafeMembers: []models.SafeMember{
			{MemberName: "alice", MemberType: "User", SafeName: "Approved", Permissions: perms("useAccounts", "accessWithoutConfirmation")},
			{MemberName: "bob", MemberType: "User", SafeName: "Approved", Permissions: perms("useAccounts")},
			{MemberName: "carol", MemberType: "User", SafeName: "Approved", Permissions: perms("requestsAuthorizationLevel1", "manageSafeMembers")},
			{MemberName: "dave", MemberType: "User", SafeName: "Unapproved", Permissions: perms("retrieveAccounts")},
			{MemberName: "erin", MemberType: "User", SafeName: "Unapproved", Permissions: perms("manageSafe", "retrieveAccounts")},
			{MemberName: "frank", MemberType: "User", SafeName: "plain", Permissions: perms("retrieveAccounts")},
			{MemberName: "ghost", MemberType: "User", SafeName: "plain", Permissions: perms("useAccounts")},
		},
	}
}

func TestComputeFindings_AccessReview(t *testing.T) {
	og, err := BuildOpenGraph(reviewVault(), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	fs := ComputeFindings(og)

	want := map[string]map[string]string{
		// alice skips the approval bob needs.
		"DUAL_CONTROL_BYPASS": {"CAUSER-ALICE-TEST": "CASAFE-APPROVED-TEST"},
		// Account 2 needs an approval nobody in its safe can give.
		"DUAL_CONTROL_NO_APPROVERS": {"CAACCOUNT-2-TEST": ""},
		// carol manages the members of a safe whose accounts she cannot use;
		// erin can grant access too, but already has it.
		"GRANT_WITHOUT_ACCESS": {"CAUSER-CAROL-TEST": "CASAFE-APPROVED-TEST"},
		// dave is disabled and erin suspended; idle is disabled but holds nothing.
		"INACTIVE_USER_WITH_ACCESS": {"CAUSER-DAVE-TEST": "", "CAUSER-ERIN-TEST": ""},
		// Account 3 reports no secret-management state, so it is not judged.
		"ACCOUNT_NOT_MANAGED": {"CAACCOUNT-2-TEST": ""},
		// ghost is a safe member that the user list does not contain.
		"UNLISTED_PRINCIPAL_WITH_ACCESS": {"CAUSER-GHOST-TEST": ""},
	}
	for id, objects := range want {
		got := findingObjectIDs(findingByID(fs, id))
		if len(got) != len(objects) {
			t.Errorf("%s: got objects %v, want %v", id, got, objects)
			continue
		}
		for obj, target := range objects {
			if gotTarget, ok := got[obj]; !ok || gotTarget != target {
				t.Errorf("%s: got objects %v, want %v", id, got, objects)
			}
		}
	}
	if len(fs) > 0 && fs[len(fs)-1].ID != "UNLISTED_PRINCIPAL_WITH_ACCESS" {
		t.Errorf("the Low finding should be listed last, got %s", fs[len(fs)-1].ID)
	}
}

// The basic user list does not say whether a user is enabled, so every user
// then reads as disabled; none of them may be reported for it.
func TestComputeFindings_EnabledNotReported(t *testing.T) {
	in := reviewVault()
	for i := range in.Users {
		in.Users[i].Enabled = false
		in.Users[i].Suspended = false
	}
	og, _ := BuildOpenGraph(in, quietLogger())
	if f := findingByID(ComputeFindings(og), "INACTIVE_USER_WITH_ACCESS"); f != nil {
		t.Errorf("users were reported as inactive although PVWA reported no enabled flag: %+v", f.Objects)
	}
}

// Safe names are case-insensitive in CyberArk, and the members and accounts
// APIs do not always spell a safe the same way.
func TestSafeNamesMatchCaseInsensitively(t *testing.T) {
	og, _ := BuildOpenGraph(reviewVault(), quietLogger())

	var frank bool
	for _, e := range edgesOfKind(og, "CyberArk_HasAccessTo") {
		if e.Start.Value == "CAUSER-FRANK-TEST" && e.End.Value == "CAACCOUNT-3-TEST" {
			frank = true
		}
	}
	if !frank {
		t.Error("a member of safe 'plain' got no access to the account listed in safe 'PLAIN'")
	}
	for _, e := range edgesOfKind(og, "CyberArk_Contains") {
		if e.End.Value == "CAACCOUNT-3-TEST" && e.Start.Value != "CASAFE-PLAIN-TEST" {
			t.Errorf("account 3 is contained in %s", e.Start.Value)
		}
	}
	if n := og.Nodes["CASAFE-PLAIN-TEST"]; n == nil || boolProp(n.Properties, "placeholder") {
		t.Error("safe Plain became a placeholder")
	}
}

func TestApprovalPropertiesOnAccessEdges(t *testing.T) {
	og, _ := BuildOpenGraph(reviewVault(), quietLogger())
	for _, e := range edgesOfKind(og, "CyberArk_HasAccessTo") {
		requires, bypasses := boolProp(e.Props, "requiresApproval"), boolProp(e.Props, "bypassesApproval")
		_, hasBypass := e.Props["bypassesApproval"]
		switch e.Start.Value {
		case "CAUSER-ALICE-TEST":
			if requires || !bypasses {
				t.Errorf("alice: requiresApproval=%v bypassesApproval=%v", requires, bypasses)
			}
		case "CAUSER-BOB-TEST":
			if !requires || hasBypass {
				t.Errorf("bob: requiresApproval=%v, bypassesApproval present=%v", requires, hasBypass)
			}
		default:
			if requires || hasBypass {
				t.Errorf("%s: requiresApproval=%v, bypassesApproval present=%v", e.Start.Value, requires, hasBypass)
			}
		}
	}
}

func TestClassifyActivity(t *testing.T) {
	for action, want := range map[string]string{
		"Retrieve password":       activityRetrieve,
		"Show Password":           activityRetrieve,
		"Copy Password":           activityRetrieve,
		"PSM Connect":             activityConnect,
		"Connect":                 activityConnect,
		"CPM Verify Password":     activityCPM,
		"CPM Change Password":     activityCPM,
		" cpm reconcile password": activityCPM,
		"Rename File":             activityOther,
		"":                        activityOther,
	} {
		if got := classifyActivity(action); got != want {
			t.Errorf("classifyActivity(%q) = %q, want %q", action, got, want)
		}
	}
}

func TestUsedAccountEdgesSeparatePeopleFromCPM(t *testing.T) {
	in := BuildInput{
		PVWATag:  "TEST",
		Users:    []models.User{{Username: "alice"}, {Username: "PasswordManager"}},
		Safes:    []models.Safe{{SafeName: "S"}},
		Accounts: []models.Account{{ID: "1", UserName: "a1", SafeName: "S"}},
		AccountActivities: map[string][]models.AccountActivity{"1": {
			{User: "alice", Action: "Retrieve password", Date: float64(1700000000)},
			{User: "alice", Action: "PSM Connect", Date: float64(1700000100)},
			{User: "alice", Action: "Rename File", Date: float64(1700000200)},
			{User: "PasswordManager", Action: "CPM Verify Password", Date: float64(1700000300)},
			{User: "PasswordManager", Action: "CPM Change Password", Date: float64(1700000400)},
		}},
	}
	og, _ := BuildOpenGraph(in, quietLogger())
	edges := edgesOfKind(og, "CyberArk_UsedAccount")
	if len(edges) != 2 {
		t.Fatalf("got %d CyberArk_UsedAccount edges, want 2", len(edges))
	}
	for _, e := range edges {
		var want map[string]interface{}
		switch e.Start.Value {
		case "CAUSER-ALICE-TEST":
			want = map[string]interface{}{"usageCount": 3, "retrieveCount": 1, "connectCount": 1, "cpmCount": 0, "credentialAccess": true}
		case "CAUSER-PASSWORDMANAGER-TEST":
			want = map[string]interface{}{"usageCount": 2, "retrieveCount": 0, "connectCount": 0, "cpmCount": 2, "credentialAccess": false}
		default:
			t.Fatalf("unexpected edge from %s", e.Start.Value)
		}
		for k, v := range want {
			if e.Props[k] != v {
				t.Errorf("%s: %s = %v, want %v", e.Start.Value, k, e.Props[k], v)
			}
		}
	}
}
