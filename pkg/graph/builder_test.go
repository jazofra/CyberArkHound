package graph

import (
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

// helper: collect edges by kind from InternalEdges
func edgesByKind(og *OpenGraph, kind string) []*Edge {
	var out []*Edge
	for _, e := range og.InternalEdges {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// helper: collect SyncsToADUser edges from ExternalEdges
func syncsToADUserEdges(og *OpenGraph) []*Edge {
	var out []*Edge
	for _, e := range og.ExternalEdges {
		if e.Kind == "SyncsToADUser" {
			out = append(out, e)
		}
	}
	return out
}

func buildWithAccounts(accounts []models.Account, targetDomains []string) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	og, _ := BuildOpenGraph(
		nil,           // users
		nil,           // groups
		nil,           // safes
		nil,           // safeMembers
		accounts,      // accounts
		targetDomains, // targetDomains
		false,         // parseSAMAccountNameFromDN
		"PVWA",        // pvwaTag
		nil,           // accountActivities
		nil,           // platforms
		nil,           // platformConnectors
		nil,           // targetPlatforms
		nil,           // linkedAccounts
		logger,
		false,  // debug
		"WARNING",
	)
	return og
}

func TestSyncsToADUser_MatchingAddress(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{{
			ID:       "acc1",
			UserName: "admin@corp.local",
			Address:  "corp.local",
			SafeName: "TestSafe",
		}},
		[]string{"corp.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 1 {
		t.Fatalf("expected 1 SyncsToADUser edge, got %d", len(edges))
	}
	if edges[0].End.Value != "ADMIN@CORP.LOCAL" {
		t.Errorf("expected end value ADMIN@CORP.LOCAL, got %s", edges[0].End.Value)
	}
	if edges[0].End.MatchBy != "name" {
		t.Errorf("expected end match_by 'name', got %s", edges[0].End.MatchBy)
	}
}

func TestSyncsToADUser_NonMatchingAddress(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{{
			ID:       "acc1",
			UserName: "admin@other.local",
			Address:  "other.local",
			SafeName: "TestSafe",
		}},
		[]string{"corp.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 0 {
		t.Fatalf("expected 0 SyncsToADUser edges, got %d", len(edges))
	}
}

func TestSyncsToADUser_SubdomainAddress(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{{
			ID:       "acc1",
			UserName: "admin@corp.local",
			Address:  "server.corp.local",
			SafeName: "TestSafe",
		}},
		[]string{"corp.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 0 {
		t.Fatalf("expected 0 SyncsToADUser edges for subdomain address, got %d", len(edges))
	}
}

func TestSyncsToADUser_EmptyUserName(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{{
			ID:       "acc1",
			UserName: "",
			Address:  "corp.local",
			SafeName: "TestSafe",
		}},
		[]string{"corp.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 0 {
		t.Fatalf("expected 0 SyncsToADUser edges for empty UserName, got %d", len(edges))
	}
}

func TestSyncsToADUser_MultipleDomains(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{
			{ID: "acc1", UserName: "admin@lab.local", Address: "lab.local", SafeName: "S1"},
			{ID: "acc2", UserName: "svc@corp.local", Address: "corp.local", SafeName: "S2"},
			{ID: "acc3", UserName: "nobody@other.local", Address: "other.local", SafeName: "S3"},
		},
		[]string{"corp.local", "lab.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 2 {
		t.Fatalf("expected 2 SyncsToADUser edges, got %d", len(edges))
	}

	endValues := map[string]bool{}
	for _, e := range edges {
		endValues[e.End.Value] = true
	}
	if !endValues["ADMIN@LAB.LOCAL"] {
		t.Error("missing edge for ADMIN@LAB.LOCAL")
	}
	if !endValues["SVC@CORP.LOCAL"] {
		t.Error("missing edge for SVC@CORP.LOCAL")
	}
}

func TestSyncsToADUser_UsernameWithoutAtSign(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{{
			ID:       "acc1",
			UserName: "administrator",
			Address:  "corp.local",
			SafeName: "TestSafe",
		}},
		[]string{"corp.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 1 {
		t.Fatalf("expected 1 SyncsToADUser edge for username without @, got %d", len(edges))
	}
	if edges[0].End.Value != "ADMINISTRATOR@CORP.LOCAL" {
		t.Errorf("expected ADMINISTRATOR@CORP.LOCAL, got %s", edges[0].End.Value)
	}
}

func TestSyncsToADUser_CaseInsensitiveMatching(t *testing.T) {
	og := buildWithAccounts(
		[]models.Account{{
			ID:       "acc1",
			UserName: "Admin@CORP.LOCAL",
			Address:  "CORP.LOCAL",
			SafeName: "TestSafe",
		}},
		[]string{"corp.local"},
	)

	edges := syncsToADUserEdges(og)
	if len(edges) != 1 {
		t.Fatalf("expected 1 SyncsToADUser edge with case-insensitive matching, got %d", len(edges))
	}
}

// buildDualControlGraph is a helper that creates a graph with the given platforms,
// accounts, and safe members to test dual control logic.
func buildDualControlGraph(platforms []models.Platform, accounts []models.Account, safeMembers []models.SafeMember) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	safes := []models.Safe{{SafeName: "TestSafe", SafeUrlId: "TestSafe"}}

	og, _ := BuildOpenGraph(
		nil,           // users
		nil,           // groups
		safes,         // safes
		safeMembers,   // safeMembers
		accounts,      // accounts
		nil,           // targetDomains
		false,         // parseSAMAccountNameFromDN
		"PVWA",        // pvwaTag
		nil,           // accountActivities
		platforms,     // platforms
		nil,           // platformConnectors
		nil,           // targetPlatforms
		nil,           // linkedAccounts
		logger,
		false,   // debug
		"WARNING",
	)
	return og
}

func TestDualControl_PlatformEnabled_WithApprovers(t *testing.T) {
	// Platform has DC enabled + safe has approvers → requiresApproval=true
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
			RequireDualControlPasswordAccessApproval: true,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
		{MemberName: "approver", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"RequestsAuthorizationLevel1": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresApproval"] != true {
		t.Errorf("expected requiresApproval=true, got %v", edges[0].Props["requiresApproval"])
	}
}

func TestDualControl_PlatformDisabled_WithApprovers(t *testing.T) {
	// Platform has DC disabled + safe has approvers → requiresApproval=false
	// (approver permissions exist but Master Policy doesn't require DC)
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
			RequireDualControlPasswordAccessApproval: false,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
		{MemberName: "approver", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"RequestsAuthorizationLevel1": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresApproval"] != false {
		t.Errorf("expected requiresApproval=false (platform DC disabled), got %v", edges[0].Props["requiresApproval"])
	}
}

func TestDualControl_PlatformEnabled_NoApprovers(t *testing.T) {
	// Platform has DC enabled but safe has no approvers → requiresApproval=false
	// (DC is unenforceable without anyone to approve)
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
			RequireDualControlPasswordAccessApproval: true,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresApproval"] != false {
		t.Errorf("expected requiresApproval=false (no approvers), got %v", edges[0].Props["requiresApproval"])
	}
}

func TestDualControl_AccessWithoutConfirmation(t *testing.T) {
	// Platform has DC enabled + approvers exist but member has accessWithoutConfirmation
	// → requiresApproval=false
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
			RequireDualControlPasswordAccessApproval: true,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{
				"UseAccounts":              true,
				"AccessWithoutConfirmation": true,
			}},
		{MemberName: "approver", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"RequestsAuthorizationLevel1": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresApproval"] != false {
		t.Errorf("expected requiresApproval=false (accessWithoutConfirmation), got %v", edges[0].Props["requiresApproval"])
	}
}

func TestDualControl_NoPlatformData_FallbackHeuristic(t *testing.T) {
	// No platforms provided → falls back to approver-presence heuristic
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
		{MemberName: "approver", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"RequestsAuthorizationLevel1": true}},
	}

	og := buildDualControlGraph(nil, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresApproval"] != true {
		t.Errorf("expected requiresApproval=true (fallback heuristic with approvers), got %v", edges[0].Props["requiresApproval"])
	}
}

func TestDualControl_NoPlatformData_NoApprovers(t *testing.T) {
	// No platforms + no approvers → requiresApproval=false
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(nil, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresApproval"] != false {
		t.Errorf("expected requiresApproval=false (no approvers), got %v", edges[0].Props["requiresApproval"])
	}
}

func TestDualControl_MixedPlatforms_PerAccountDetermination(t *testing.T) {
	// Two accounts in the same safe, different platforms — one with DC, one without
	platforms := []models.Platform{
		{
			General: models.PlatformGeneral{ID: "WinDC", Name: "WinDC"},
			PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
				RequireDualControlPasswordAccessApproval: true,
			},
		},
		{
			General: models.PlatformGeneral{ID: "WinNoDC", Name: "WinNoDC"},
			PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
				RequireDualControlPasswordAccessApproval: false,
			},
		},
	}
	accounts := []models.Account{
		{ID: "acc1", UserName: "admin1", SafeName: "TestSafe", PlatformID: "WinDC"},
		{ID: "acc2", UserName: "admin2", SafeName: "TestSafe", PlatformID: "WinNoDC"},
	}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
		{MemberName: "approver", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"RequestsAuthorizationLevel1": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArkHasAccessTo edges, got %d", len(edges))
	}

	// Build a map of end node → requiresApproval
	approvalByEnd := make(map[string]bool)
	for _, e := range edges {
		approvalByEnd[e.End.Value] = e.Props["requiresApproval"].(bool)
	}

	acc1NodeID := "CAACCOUNT-ACC1-PVWA"
	acc2NodeID := "CAACCOUNT-ACC2-PVWA"

	if !approvalByEnd[acc1NodeID] {
		t.Errorf("expected requiresApproval=true for acc1 (WinDC platform), got false")
	}
	if approvalByEnd[acc2NodeID] {
		t.Errorf("expected requiresApproval=false for acc2 (WinNoDC platform), got true")
	}
}

func TestSessionMonitoring_PlatformEnabled(t *testing.T) {
	// Platform has session monitoring and recording enabled → edge properties true
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		SessionManagement: models.PlatformSessionManagement{
			RequirePrivilegedSessionMonitoringAndIsolation: true,
			RecordAndSaveSessionActivity:                   true,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresSessionMonitoring"] != true {
		t.Errorf("expected requiresSessionMonitoring=true, got %v", edges[0].Props["requiresSessionMonitoring"])
	}
	if edges[0].Props["recordsSessionActivity"] != true {
		t.Errorf("expected recordsSessionActivity=true, got %v", edges[0].Props["recordsSessionActivity"])
	}
}

func TestSessionMonitoring_PlatformDisabled(t *testing.T) {
	// Platform has session monitoring disabled → edge properties false
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		SessionManagement: models.PlatformSessionManagement{
			RequirePrivilegedSessionMonitoringAndIsolation: false,
			RecordAndSaveSessionActivity:                   false,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresSessionMonitoring"] != false {
		t.Errorf("expected requiresSessionMonitoring=false, got %v", edges[0].Props["requiresSessionMonitoring"])
	}
	if edges[0].Props["recordsSessionActivity"] != false {
		t.Errorf("expected recordsSessionActivity=false, got %v", edges[0].Props["recordsSessionActivity"])
	}
}

func TestSessionMonitoring_NoPlatformData(t *testing.T) {
	// No platforms → session properties default to false
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(nil, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresSessionMonitoring"] != false {
		t.Errorf("expected requiresSessionMonitoring=false (no platform data), got %v", edges[0].Props["requiresSessionMonitoring"])
	}
	if edges[0].Props["recordsSessionActivity"] != false {
		t.Errorf("expected recordsSessionActivity=false (no platform data), got %v", edges[0].Props["recordsSessionActivity"])
	}
}

func TestSessionMonitoring_MixedPlatforms(t *testing.T) {
	// Two accounts on different platforms — one with monitoring, one without
	platforms := []models.Platform{
		{
			General: models.PlatformGeneral{ID: "WinMon", Name: "WinMon"},
			SessionManagement: models.PlatformSessionManagement{
				RequirePrivilegedSessionMonitoringAndIsolation: true,
				RecordAndSaveSessionActivity:                   true,
			},
		},
		{
			General: models.PlatformGeneral{ID: "WinNoMon", Name: "WinNoMon"},
			SessionManagement: models.PlatformSessionManagement{
				RequirePrivilegedSessionMonitoringAndIsolation: false,
				RecordAndSaveSessionActivity:                   false,
			},
		},
	}
	accounts := []models.Account{
		{ID: "acc1", UserName: "admin1", SafeName: "TestSafe", PlatformID: "WinMon"},
		{ID: "acc2", UserName: "admin2", SafeName: "TestSafe", PlatformID: "WinNoMon"},
	}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArkHasAccessTo edges, got %d", len(edges))
	}

	monByEnd := make(map[string]bool)
	recByEnd := make(map[string]bool)
	for _, e := range edges {
		monByEnd[e.End.Value] = e.Props["requiresSessionMonitoring"].(bool)
		recByEnd[e.End.Value] = e.Props["recordsSessionActivity"].(bool)
	}

	acc1NodeID := "CAACCOUNT-ACC1-PVWA"
	acc2NodeID := "CAACCOUNT-ACC2-PVWA"

	if !monByEnd[acc1NodeID] {
		t.Errorf("expected requiresSessionMonitoring=true for acc1 (WinMon), got false")
	}
	if monByEnd[acc2NodeID] {
		t.Errorf("expected requiresSessionMonitoring=false for acc2 (WinNoMon), got true")
	}
	if !recByEnd[acc1NodeID] {
		t.Errorf("expected recordsSessionActivity=true for acc1 (WinMon), got false")
	}
	if recByEnd[acc2NodeID] {
		t.Errorf("expected recordsSessionActivity=false for acc2 (WinNoMon), got true")
	}
}

func TestSessionMonitoring_PartialSettings(t *testing.T) {
	// Platform has monitoring enabled but recording disabled — each is independent
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		SessionManagement: models.PlatformSessionManagement{
			RequirePrivilegedSessionMonitoringAndIsolation: true,
			RecordAndSaveSessionActivity:                   false,
		},
	}}
	accounts := []models.Account{{
		ID: "acc1", UserName: "admin", SafeName: "TestSafe", PlatformID: "WinServer",
	}}
	members := []models.SafeMember{
		{MemberName: "accessor", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"UseAccounts": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArkHasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArkHasAccessTo edge, got %d", len(edges))
	}
	if edges[0].Props["requiresSessionMonitoring"] != true {
		t.Errorf("expected requiresSessionMonitoring=true, got %v", edges[0].Props["requiresSessionMonitoring"])
	}
	if edges[0].Props["recordsSessionActivity"] != false {
		t.Errorf("expected recordsSessionActivity=false, got %v", edges[0].Props["recordsSessionActivity"])
	}
}

// buildPlatformGraph creates a graph with platforms, connectors, and target platforms for testing.
func buildPlatformGraph(platforms []models.Platform, platformConnectors map[string][]string, targetPlatforms []models.TargetPlatform) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	og, _ := BuildOpenGraph(
		nil,                // users
		nil,                // groups
		nil,                // safes
		nil,                // safeMembers
		nil,                // accounts
		nil,                // targetDomains
		false,              // parseSAMAccountNameFromDN
		"PVWA",             // pvwaTag
		nil,                // accountActivities
		platforms,          // platforms
		platformConnectors, // platformConnectors
		targetPlatforms,    // targetPlatforms
		nil,                // linkedAccounts
		logger,
		false,  // debug
		"WARNING",
	)
	return og
}

func TestPlatformConnectionComponents(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}
	connectors := map[string][]string{
		"WinServer": {"PSM-RDP", "PSM-SSH"},
	}

	og := buildPlatformGraph(platforms, connectors, nil)
	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected CyberArkPlatform node, got nil")
	}

	cc, ok := node.Properties["connectionComponents"]
	if !ok {
		t.Fatal("expected connectionComponents property to be set")
	}
	ccSlice, ok := cc.([]string)
	if !ok {
		t.Fatalf("expected connectionComponents to be []string, got %T", cc)
	}
	if len(ccSlice) != 2 || ccSlice[0] != "PSM-RDP" || ccSlice[1] != "PSM-SSH" {
		t.Errorf("expected [PSM-RDP, PSM-SSH], got %v", ccSlice)
	}
}

func TestPlatformConnectionComponents_Empty(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}

	og := buildPlatformGraph(platforms, nil, nil)
	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected CyberArkPlatform node, got nil")
	}

	if _, ok := node.Properties["connectionComponents"]; ok {
		t.Error("expected connectionComponents property to be absent when no connectors provided")
	}
}

func TestPlatformExceptionFlags_Set(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		PrivilegedAccessWorkflows: models.PlatformPrivilegedAccessWorkflows{
			RequireDualControlPasswordAccessApproval: false,
		},
	}}
	targetPlatforms := []models.TargetPlatform{{
		PlatformID: "WinServer",
		PrivilegedAccessWorkflows: models.TargetPlatformWorkflows{
			RequireDualControlPasswordAccessApproval: models.WorkflowRule{IsActive: false, IsAnException: true},
			EnforceCheckinCheckoutExclusiveAccess:    models.WorkflowRule{IsActive: false, IsAnException: false},
			EnforceOnetimePasswordAccess:             models.WorkflowRule{IsActive: false, IsAnException: false},
		},
		SessionManagement: models.TargetPlatformSessionManagement{
			RequirePrivilegedSessionMonitoringAndIsolation: models.WorkflowRule{IsActive: true, IsAnException: true},
			RecordAndSaveSessionActivity:                   models.WorkflowRule{IsActive: false, IsAnException: false},
		},
	}}

	og := buildPlatformGraph(platforms, nil, targetPlatforms)
	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected CyberArkPlatform node, got nil")
	}

	if node.Properties["dualControlIsException"] != true {
		t.Errorf("expected dualControlIsException=true, got %v", node.Properties["dualControlIsException"])
	}
	if node.Properties["exclusiveAccessIsException"] != false {
		t.Errorf("expected exclusiveAccessIsException=false, got %v", node.Properties["exclusiveAccessIsException"])
	}
	if node.Properties["sessionMonitoringIsException"] != true {
		t.Errorf("expected sessionMonitoringIsException=true, got %v", node.Properties["sessionMonitoringIsException"])
	}
}

func TestPlatformExceptionFlags_NotSet(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}
	targetPlatforms := []models.TargetPlatform{{
		PlatformID: "WinServer",
		PrivilegedAccessWorkflows: models.TargetPlatformWorkflows{
			RequireDualControlPasswordAccessApproval: models.WorkflowRule{IsActive: true, IsAnException: false},
			EnforceCheckinCheckoutExclusiveAccess:    models.WorkflowRule{IsActive: false, IsAnException: false},
			EnforceOnetimePasswordAccess:             models.WorkflowRule{IsActive: false, IsAnException: false},
		},
		SessionManagement: models.TargetPlatformSessionManagement{
			RequirePrivilegedSessionMonitoringAndIsolation: models.WorkflowRule{IsActive: true, IsAnException: false},
			RecordAndSaveSessionActivity:                   models.WorkflowRule{IsActive: true, IsAnException: false},
		},
	}}

	og := buildPlatformGraph(platforms, nil, targetPlatforms)
	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected CyberArkPlatform node, got nil")
	}

	if node.Properties["dualControlIsException"] != false {
		t.Errorf("expected dualControlIsException=false, got %v", node.Properties["dualControlIsException"])
	}
	if node.Properties["exclusiveAccessIsException"] != false {
		t.Errorf("expected exclusiveAccessIsException=false, got %v", node.Properties["exclusiveAccessIsException"])
	}
	if node.Properties["otpIsException"] != false {
		t.Errorf("expected otpIsException=false, got %v", node.Properties["otpIsException"])
	}
	if node.Properties["sessionMonitoringIsException"] != false {
		t.Errorf("expected sessionMonitoringIsException=false, got %v", node.Properties["sessionMonitoringIsException"])
	}
	if node.Properties["sessionRecordingIsException"] != false {
		t.Errorf("expected sessionRecordingIsException=false, got %v", node.Properties["sessionRecordingIsException"])
	}
}

func TestPlatformExceptionFlags_NoTargetData(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}

	og := buildPlatformGraph(platforms, nil, nil)
	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected CyberArkPlatform node, got nil")
	}

	// Exception flags should not be present when no target platform data
	for _, key := range []string{"dualControlIsException", "exclusiveAccessIsException", "otpIsException", "sessionMonitoringIsException", "sessionRecordingIsException"} {
		if _, ok := node.Properties[key]; ok {
			t.Errorf("expected %s to be absent when no target data, but it was present", key)
		}
	}
}
