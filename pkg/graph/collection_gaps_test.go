package graph

import (
	"strings"
	"testing"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

func quietLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	return logger
}

func TestExpiredSafeMembershipCreatesNoEdges(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	past := float64(now.Add(-24 * time.Hour).Unix())
	future := float64(now.Add(24 * time.Hour).Unix())

	og, err := BuildOpenGraph(BuildInput{
		Users: []models.User{{Username: "expired"}, {Username: "current"}},
		Safes: []models.Safe{{SafeName: "S1"}},
		SafeMembers: []models.SafeMember{
			{MemberName: "expired", MemberType: "User", SafeName: "S1", MembershipExpirationDate: past,
				Permissions: map[string]interface{}{"retrieveAccounts": true, "manageSafeMembers": true, "requestsAuthorizationLevel1": true}},
			{MemberName: "current", MemberType: "User", SafeName: "S1", MembershipExpirationDate: future,
				Permissions: map[string]interface{}{"useAccounts": true}},
		},
		Accounts: []models.Account{{ID: "1_1", UserName: "svc", SafeName: "S1"}},
		PVWATag:  "PVWA",
		Now:      now,
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"CyberArk_HasAccessTo", "CyberArk_CanGrantAccessTo", "CyberArk_CanApprove"} {
		for _, e := range edgesByKind(og, kind) {
			if e.Start.Value == "CAUSER-EXPIRED-PVWA" {
				t.Errorf("expired member must not have a %s edge", kind)
			}
		}
	}

	access := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(access) != 1 || access[0].Start.Value != "CAUSER-CURRENT-PVWA" {
		t.Fatalf("expected only the current member's access edge, got %+v", access)
	}
	// The expired approver must not make dual control look enforceable.
	if access[0].Props["requiresApproval"] != false {
		t.Errorf("requiresApproval = %v; an expired approver cannot approve", access[0].Props["requiresApproval"])
	}

	perms, _ := og.Nodes["CAUSER-EXPIRED-PVWA"].Properties["safePermissions"].(string)
	if !strings.Contains(perms, `"membershipExpired":true`) {
		t.Errorf("expired membership should still be listed with membershipExpired=true, got %s", perms)
	}
}

func TestGroupMemberListCreatesMemberOfEdges(t *testing.T) {
	og, err := BuildOpenGraph(BuildInput{
		Users: []models.User{
			// alice reports the membership herself; bob's details were not
			// available, so only the group's member list knows about him.
			{Username: "alice", GroupsMembership: []models.UserGroupMembership{{GroupName: "Ops"}}},
			{Username: "bob"},
		},
		Groups: []models.Group{{
			ID: 7, GroupName: "Ops",
			Members: []models.GroupMember{
				{Username: "alice"},
				{Username: "bob"},
				{MemberName: "Nested", MemberType: "Group"},
			},
		}},
		PVWATag: "PVWA",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, e := range edgesByKind(og, "CyberArk_MemberOf") {
		if _, dup := got[e.Start.Value]; dup {
			t.Fatalf("duplicate MemberOf edge for %s", e.Start.Value)
		}
		if e.End.Value != "CAGROUP-OPS-PVWA" {
			t.Fatalf("unexpected MemberOf target %s", e.End.Value)
		}
		got[e.Start.Value], _ = e.Props["source"].(string)
	}
	want := map[string]string{
		"CAUSER-ALICE-PVWA":   "userDetails",
		"CAUSER-BOB-PVWA":     "groupMembers",
		"CAGROUP-NESTED-PVWA": "groupMembers",
	}
	if len(got) != len(want) {
		t.Fatalf("MemberOf edges = %v, want %v", got, want)
	}
	for start, source := range want {
		if got[start] != source {
			t.Errorf("edge from %s has source %q, want %q", start, got[start], source)
		}
	}
}

func TestTargetDomainsAreNormalized(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{
			{ID: "1", UserName: "admin", Address: "corp.local", SafeName: "S"},
			{ID: "2", UserName: "local", Address: "srv01.corp.local", SafeName: "S"},
		},
		[]string{" corp.local. ", ""},
	)

	sync := syncsToADUserEdges(og)
	if len(sync) != 1 || sync[0].End.Value != "ADMIN@CORP.LOCAL" {
		t.Fatalf("SyncsToADUser = %+v, want ADMIN@CORP.LOCAL", sync)
	}
	if sync[0].Props["domain"] != "corp.local" {
		t.Errorf("domain property = %q, want trimmed corp.local", sync[0].Props["domain"])
	}
	conn := externalEdgesByKind(og, "CyberArk_CanConnect")
	if len(conn) != 1 || conn[0].End.Value != "SRV01.CORP.LOCAL" {
		t.Fatalf("CanConnect = %+v, want SRV01.CORP.LOCAL", conn)
	}
}

func TestApplicationWithUnknownAuthenticationsIsNotUnrestricted(t *testing.T) {
	og, err := BuildOpenGraph(BuildInput{
		Applications: []models.Application{{AppID: "Mystery", AuthenticationsUnknown: true}},
		SafeMembers: []models.SafeMember{{MemberName: "Mystery", MemberType: "Application", SafeName: "S1",
			Permissions: map[string]interface{}{"retrieveAccounts": true}}},
		Accounts: []models.Account{{ID: "1_1", SafeName: "S1"}},
		PVWATag:  "PVWA",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	node := og.Nodes["CAAPP-MYSTERY-PVWA"]
	if node == nil {
		t.Fatal("application node missing")
	}
	if node.Properties["isUnrestricted"] != false {
		t.Errorf("isUnrestricted = %v, want false when restrictions are unknown", node.Properties["isUnrestricted"])
	}
	if node.Properties["authenticationsUnknown"] != true {
		t.Errorf("authenticationsUnknown = %v, want true", node.Properties["authenticationsUnknown"])
	}
	for _, f := range ComputeFindings(og) {
		if f.ID == "CCP_UNRESTRICTED_APP" || f.ID == "CCP_UNRESTRICTED_RETRIEVAL" {
			t.Errorf("unexpected finding %s for an application whose restrictions are unknown", f.ID)
		}
	}
}

func TestNumericIDsAreNotRenderedInExponentForm(t *testing.T) {
	og, err := BuildOpenGraph(BuildInput{
		Users:   []models.User{{ID: float64(1234567), Username: "big"}, {Username: "noid"}},
		Groups:  []models.Group{{ID: float64(2345678)}},
		PVWATag: "PVWA",
	}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := og.Nodes["CAUSER-BIG-PVWA"].Properties["userId"]; got != "1234567" {
		t.Errorf("userId = %v, want 1234567", got)
	}
	if got, ok := og.Nodes["CAUSER-NOID-PVWA"].Properties["userId"]; ok && got != "" {
		t.Errorf("userId for a user without an ID = %v, want empty", got)
	}
	// A group without a name falls back to its ID for its node.
	if og.Nodes["CAGROUP-2345678-PVWA"] == nil {
		t.Errorf("group node keyed by integer ID missing; nodes: %v", og.Nodes)
	}
}

func TestPermissionListsAreDeterministic(t *testing.T) {
	perms := map[string]interface{}{}
	for _, p := range []string{"useAccounts", "retrieveAccounts", "listAccounts", "addAccounts", "manageSafe", "updateAccountProperties", "viewSafeMembers"} {
		perms[p] = true
	}
	build := func() string {
		og, err := BuildOpenGraph(BuildInput{
			Users:       []models.User{{Username: "alice"}},
			Safes:       []models.Safe{{SafeName: "S1"}},
			SafeMembers: []models.SafeMember{{MemberName: "alice", MemberType: "User", SafeName: "S1", Permissions: perms}},
			Accounts:    []models.Account{{ID: "1_1", SafeName: "S1"}},
			PVWATag:     "PVWA",
		}, quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		access := edgesByKind(og, "CyberArk_HasAccessTo")
		if len(access) != 1 {
			t.Fatalf("expected 1 access edge, got %d", len(access))
		}
		return strings.Join(access[0].Props["permissions"].([]string), ",") + "|" +
			og.Nodes["CAUSER-ALICE-PVWA"].Properties["safePermissions"].(string)
	}
	first := build()
	// Map iteration order is randomised per range loop; repeat enough times
	// that an unsorted list would almost surely come out in another order.
	for i := 0; i < 20; i++ {
		if got := build(); got != first {
			t.Fatalf("permission lists differ between identical builds:\n%s\n%s", first, got)
		}
	}
}
