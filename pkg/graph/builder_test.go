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

func externalEdgesByKind(og *OpenGraph, kind string) []*Edge {
	var out []*Edge
	for _, e := range og.ExternalEdges {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// helper: collect CyberArk_SyncsToADUser edges from ExternalEdges
func syncsToADUserEdges(og *OpenGraph) []*Edge {
	var out []*Edge
	for _, e := range og.ExternalEdges {
		if e.Kind == "CyberArk_SyncsToADUser" {
			out = append(out, e)
		}
	}
	return out
}

func buildWithAccounts(accounts []models.Account, targetDomains []string) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	og, _ := BuildOpenGraph(BuildInput{
		Accounts:      accounts,
		TargetDomains: targetDomains,
		PVWATag:       "PVWA",
		LogLevel:      "WARNING",
	}, logger)
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
		t.Fatalf("expected 1 CyberArk_SyncsToADUser edge, got %d", len(edges))
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
		t.Fatalf("expected 0 CyberArk_SyncsToADUser edges, got %d", len(edges))
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
		t.Fatalf("expected 0 CyberArk_SyncsToADUser edges for subdomain address, got %d", len(edges))
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
		t.Fatalf("expected 0 CyberArk_SyncsToADUser edges for empty UserName, got %d", len(edges))
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
		t.Fatalf("expected 2 CyberArk_SyncsToADUser edges, got %d", len(edges))
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
		t.Fatalf("expected 1 CyberArk_SyncsToADUser edge for username without @, got %d", len(edges))
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
		t.Fatalf("expected 1 CyberArk_SyncsToADUser edge with case-insensitive matching, got %d", len(edges))
	}
}

// buildDualControlGraph is a helper that creates a graph with the given platforms,
// accounts, and safe members to test dual control logic.
func buildDualControlGraph(platforms []models.Platform, accounts []models.Account, safeMembers []models.SafeMember) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	safes := []models.Safe{{SafeName: "TestSafe", SafeUrlId: "TestSafe"}}

	og, _ := BuildOpenGraph(BuildInput{
		Safes:       safes,
		SafeMembers: safeMembers,
		Accounts:    accounts,
		PVWATag:     "PVWA",
		Platforms:   platforms,
		LogLevel:    "WARNING",
	}, logger)
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
				"UseAccounts":               true,
				"AccessWithoutConfirmation": true,
			}},
		{MemberName: "approver", SafeName: "TestSafe", MemberType: "user",
			Permissions: map[string]interface{}{"RequestsAuthorizationLevel1": true}},
	}

	og := buildDualControlGraph(platforms, accounts, members)
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArk_HasAccessTo edges, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArk_HasAccessTo edges, got %d", len(edges))
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
	edges := edgesByKind(og, "CyberArk_HasAccessTo")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_HasAccessTo edge, got %d", len(edges))
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
	return buildFullPlatformGraph(platforms, platformConnectors, targetPlatforms, nil, nil, nil)
}

// buildFullPlatformGraph creates a graph with platforms, connectors, target platforms, PSM servers,
// connection components, and accounts for testing.
func buildFullPlatformGraph(platforms []models.Platform, platformConnectors map[string][]string, targetPlatforms []models.TargetPlatform, psmServers []models.PSMServer, connectionComponents []models.ConnectionComponent, accounts []models.Account) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	og, _ := BuildOpenGraph(BuildInput{
		Accounts:             accounts,
		PVWATag:              "PVWA",
		Platforms:            platforms,
		PlatformConnectors:   platformConnectors,
		TargetPlatforms:      targetPlatforms,
		PSMServers:           psmServers,
		ConnectionComponents: connectionComponents,
		LogLevel:             "WARNING",
	}, logger)
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
		t.Fatal("expected CyberArk_Platform node, got nil")
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
		t.Fatal("expected CyberArk_Platform node, got nil")
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
		t.Fatal("expected CyberArk_Platform node, got nil")
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
		t.Fatal("expected CyberArk_Platform node, got nil")
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
		t.Fatal("expected CyberArk_Platform node, got nil")
	}

	// Exception flags should not be present when no target platform data
	for _, key := range []string{"dualControlIsException", "exclusiveAccessIsException", "otpIsException", "sessionMonitoringIsException", "sessionRecordingIsException"} {
		if _, ok := node.Properties[key]; ok {
			t.Errorf("expected %s to be absent when no target data, but it was present", key)
		}
	}
}

func TestPSMServerNodes(t *testing.T) {
	psmServers := []models.PSMServer{
		{ID: "PSMServer_abc123", Name: "PSM Server Main", Address: "10.10.10.20"},
		{ID: "PSMServer_def456", Name: "PSM Server DR", Address: "10.10.10.21"},
	}

	og := buildFullPlatformGraph(nil, nil, nil, psmServers, nil, nil)

	node1 := og.Nodes["CAPSMSERVER-PSMSERVER_ABC123-PVWA"]
	if node1 == nil {
		t.Fatal("expected CyberArk_PSMServer node for PSMServer_abc123, got nil")
	}
	if node1.Properties["psmServerId"] != "PSMServer_abc123" {
		t.Errorf("expected psmServerId=PSMServer_abc123, got %v", node1.Properties["psmServerId"])
	}
	if node1.Properties["name"] != "PSM Server Main" {
		t.Errorf("expected name='PSM Server Main', got %v", node1.Properties["name"])
	}
	if node1.Properties["address"] != "10.10.10.20" {
		t.Errorf("expected address=10.10.10.20, got %v", node1.Properties["address"])
	}

	node2 := og.Nodes["CAPSMSERVER-PSMSERVER_DEF456-PVWA"]
	if node2 == nil {
		t.Fatal("expected CyberArk_PSMServer node for PSMServer_def456, got nil")
	}
}

func TestConnectionComponentNodes(t *testing.T) {
	connComponents := []models.ConnectionComponent{
		{ID: "PSM-RDP", DisplayName: "RDP"},
		{ID: "PSM-SSH", DisplayName: "SSH"},
	}

	og := buildFullPlatformGraph(nil, nil, nil, nil, connComponents, nil)

	node1 := og.Nodes["CACONNCOMP-PSM-RDP-PVWA"]
	if node1 == nil {
		t.Fatal("expected CyberArk_ConnectionComponent node for PSM-RDP, got nil")
	}
	if node1.Properties["connectorId"] != "PSM-RDP" {
		t.Errorf("expected connectorId=PSM-RDP, got %v", node1.Properties["connectorId"])
	}
	if node1.Properties["displayName"] != "RDP" {
		t.Errorf("expected displayName=RDP, got %v", node1.Properties["displayName"])
	}

	node2 := og.Nodes["CACONNCOMP-PSM-SSH-PVWA"]
	if node2 == nil {
		t.Fatal("expected CyberArk_ConnectionComponent node for PSM-SSH, got nil")
	}
}

func TestPSMServer_NilInput(t *testing.T) {
	og := buildFullPlatformGraph(nil, nil, nil, nil, nil, nil)
	for _, node := range og.Nodes {
		for _, kind := range node.Kinds {
			if kind == "CyberArk_PSMServer" || kind == "CyberArk_ConnectionComponent" {
				t.Errorf("expected no PSM/connector nodes when input is nil, got %s", kind)
			}
		}
	}
}

func TestCyberArk_UsesPSMServer_Edge(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		SessionManagement: models.PlatformSessionManagement{
			PSMServerID: "PSMServer_abc123",
		},
	}}
	psmServers := []models.PSMServer{
		{ID: "PSMServer_abc123", Name: "PSM Server Main", Address: "10.10.10.20"},
	}

	og := buildFullPlatformGraph(platforms, nil, nil, psmServers, nil, nil)

	edges := edgesByKind(og, "CyberArk_UsesPSMServer")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_UsesPSMServer edge, got %d", len(edges))
	}
	if edges[0].Start.Value != "CAPLATFORM-WINSERVER-PVWA" {
		t.Errorf("expected start=CAPLATFORM-WINSERVER-PVWA, got %s", edges[0].Start.Value)
	}
	if edges[0].End.Value != "CAPSMSERVER-PSMSERVER_ABC123-PVWA" {
		t.Errorf("expected end=CAPSMSERVER-PSMSERVER_ABC123-PVWA, got %s", edges[0].End.Value)
	}
}

func TestCyberArk_ManagedByPSM_Edge(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
		SessionManagement: models.PlatformSessionManagement{
			PSMServerID: "PSMServer_abc123",
		},
	}}
	psmServers := []models.PSMServer{
		{ID: "PSMServer_abc123", Name: "PSM Server Main", Address: "10.10.10.20"},
	}
	accounts := []models.Account{
		{ID: "123_45", Name: "TestAccount", PlatformID: "WinServer", SafeName: "TestSafe"},
	}

	og := buildFullPlatformGraph(platforms, nil, nil, psmServers, nil, accounts)

	edges := edgesByKind(og, "CyberArk_ManagedByPSM")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_ManagedByPSM edge, got %d", len(edges))
	}
	if edges[0].End.Value != "CAPSMSERVER-PSMSERVER_ABC123-PVWA" {
		t.Errorf("expected end=CAPSMSERVER-PSMSERVER_ABC123-PVWA, got %s", edges[0].End.Value)
	}
}

func TestCyberArk_HasConnectionComponent_Edge(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}
	connectors := map[string][]string{
		"WinServer": {"PSM-RDP", "PSM-SSH"},
	}
	connComponents := []models.ConnectionComponent{
		{ID: "PSM-RDP", DisplayName: "RDP"},
		{ID: "PSM-SSH", DisplayName: "SSH"},
	}

	og := buildFullPlatformGraph(platforms, connectors, nil, nil, connComponents, nil)

	edges := edgesByKind(og, "CyberArk_HasConnectionComponent")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArk_HasConnectionComponent edges, got %d", len(edges))
	}

	for _, e := range edges {
		if e.Start.Value != "CAPLATFORM-WINSERVER-PVWA" {
			t.Errorf("expected start=CAPLATFORM-WINSERVER-PVWA, got %s", e.Start.Value)
		}
		if e.Props["enabled"] != true {
			t.Errorf("expected enabled=true, got %v", e.Props["enabled"])
		}
	}
}

func TestCyberArk_HasConnectionComponent_NoConnectors(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}
	connComponents := []models.ConnectionComponent{
		{ID: "PSM-RDP", DisplayName: "RDP"},
	}

	og := buildFullPlatformGraph(platforms, nil, nil, nil, connComponents, nil)

	edges := edgesByKind(og, "CyberArk_HasConnectionComponent")
	if len(edges) != 0 {
		t.Errorf("expected 0 CyberArk_HasConnectionComponent edges when no platformConnectors, got %d", len(edges))
	}
}

func TestPlatformFallbackFromTargets(t *testing.T) {
	// Simulate /API/Platforms/ failure: no platforms, but target platforms available
	targetPlatforms := []models.TargetPlatform{
		{
			PlatformID:   "WinServer",
			Name:         "WinServer",
			Active:       true,
			SystemType:   "Windows",
			AllowedSafes: ".*",
			PrivilegedAccessWorkflows: models.TargetPlatformWorkflows{
				RequireDualControlPasswordAccessApproval: models.WorkflowRule{IsActive: true, IsAnException: true},
				RequireUsersToSpecifyReasonForAccess:     models.WorkflowRule{IsActive: true, IsAnException: false},
			},
			CredentialsManagementPolicy: models.TargetCredentialsManagementPolicy{
				Verification: models.TargetCredentialVerification{
					PerformAutomatic:          true,
					RequirePasswordEveryXDays: 7,
					AllowManual:               true,
				},
				Change: models.TargetCredentialChange{
					PerformAutomatic:          false,
					RequirePasswordEveryXDays: 90,
					AllowManual:               true,
				},
				Reconcile: models.TargetCredentialReconcile{
					AutomaticReconcileWhenUnsynced: true,
					AllowManual:                    true,
				},
			},
			SessionManagement: models.TargetPlatformSessionManagement{
				PSMServerID: "PSMServer_abc123",
				RequirePrivilegedSessionMonitoringAndIsolation: models.WorkflowRule{IsActive: true, IsAnException: false},
				RecordAndSaveSessionActivity:                   models.WorkflowRule{IsActive: false, IsAnException: false},
			},
		},
	}
	psmServers := []models.PSMServer{
		{ID: "PSMServer_abc123", Name: "PSM Main", Address: "10.10.10.20"},
	}
	accounts := []models.Account{
		{ID: "acc1", Name: "TestAccount", PlatformID: "WinServer", SafeName: "TestSafe"},
	}

	// No platforms passed (simulating 500 error), but targetPlatforms are available
	og := buildFullPlatformGraph(nil, nil, targetPlatforms, psmServers, nil, accounts)

	// Fallback platform node should be created from target data
	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected fallback CyberArk_Platform node from Targets data, got nil")
	}
	if node.Properties["dataSource"] != "targets-fallback" {
		t.Errorf("expected dataSource=targets-fallback, got %v", node.Properties["dataSource"])
	}
	if node.Properties["psmServerID"] != "PSMServer_abc123" {
		t.Errorf("expected psmServerID=PSMServer_abc123, got %v", node.Properties["psmServerID"])
	}
	if node.Properties["active"] != true {
		t.Errorf("expected active=true, got %v", node.Properties["active"])
	}
	if node.Properties["systemType"] != "Windows" {
		t.Errorf("expected systemType=Windows, got %v", node.Properties["systemType"])
	}
	if node.Properties["allowedSafes"] != ".*" {
		t.Errorf("expected allowedSafes=.*, got %v", node.Properties["allowedSafes"])
	}
	if node.Properties["requireUsersToSpecifyReasonForAccess"] != true {
		t.Errorf("expected requireUsersToSpecifyReasonForAccess=true, got %v", node.Properties["requireUsersToSpecifyReasonForAccess"])
	}
	if node.Properties["performPeriodicVerification"] != true {
		t.Errorf("expected performPeriodicVerification=true, got %v", node.Properties["performPeriodicVerification"])
	}
	if node.Properties["automaticReconcileWhenUnsynched"] != true {
		t.Errorf("expected automaticReconcileWhenUnsynched=true, got %v", node.Properties["automaticReconcileWhenUnsynched"])
	}

	// Exception flags should still be set
	if node.Properties["dualControlIsException"] != true {
		t.Errorf("expected dualControlIsException=true, got %v", node.Properties["dualControlIsException"])
	}

	// CyberArk_UsesPSMServer edge should exist
	psmEdges := edgesByKind(og, "CyberArk_UsesPSMServer")
	if len(psmEdges) != 1 {
		t.Fatalf("expected 1 CyberArk_UsesPSMServer edge from fallback, got %d", len(psmEdges))
	}

	// CyberArk_UsesPlatform edge (Account → Platform) should exist
	platEdges := edgesByKind(og, "CyberArk_UsesPlatform")
	if len(platEdges) != 1 {
		t.Fatalf("expected 1 CyberArk_UsesPlatform edge from fallback, got %d", len(platEdges))
	}

	// CyberArk_ManagedByPSM edge (Account → PSM Server) should exist
	managedEdges := edgesByKind(og, "CyberArk_ManagedByPSM")
	if len(managedEdges) != 1 {
		t.Fatalf("expected 1 CyberArk_ManagedByPSM edge from fallback, got %d", len(managedEdges))
	}
}

func TestPlatformFallbackNotUsedWhenPlatformsExist(t *testing.T) {
	// When /API/Platforms/ succeeds, target data should enrich, not create duplicates
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}
	targetPlatforms := []models.TargetPlatform{{
		PlatformID: "WinServer",
		Name:       "WinServer",
		PrivilegedAccessWorkflows: models.TargetPlatformWorkflows{
			RequireDualControlPasswordAccessApproval: models.WorkflowRule{IsActive: true, IsAnException: true},
		},
	}}

	og := buildFullPlatformGraph(platforms, nil, targetPlatforms, nil, nil, nil)

	node := og.Nodes["CAPLATFORM-WINSERVER-PVWA"]
	if node == nil {
		t.Fatal("expected CyberArk_Platform node, got nil")
	}

	// Should NOT have dataSource=targets-fallback since full platform data was available
	if node.Properties["dataSource"] == "targets-fallback" {
		t.Error("expected full platform data, not fallback")
	}

	// Exception flags should still be merged
	if node.Properties["dualControlIsException"] != true {
		t.Errorf("expected dualControlIsException=true, got %v", node.Properties["dualControlIsException"])
	}
}

func TestCyberArk_HasConnectionComponent_CaseInsensitive(t *testing.T) {
	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"},
	}}
	// Connector IDs from per-platform endpoint use different casing
	connectors := map[string][]string{
		"WinServer": {"psm-rdp", "PSM-SSH"},
	}
	// Connection component IDs from global endpoint use original casing
	connComponents := []models.ConnectionComponent{
		{ID: "PSM-RDP", DisplayName: "RDP"},
		{ID: "psm-ssh", DisplayName: "SSH"},
	}

	og := buildFullPlatformGraph(platforms, connectors, nil, nil, connComponents, nil)

	edges := edgesByKind(og, "CyberArk_HasConnectionComponent")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArk_HasConnectionComponent edges with case-insensitive matching, got %d", len(edges))
	}
}

func TestCyberArk_PSMServerHostedOn_Edge(t *testing.T) {
	psmServers := []models.PSMServer{
		{ID: "PSMServer_abc123", Name: "PSM Server Main", Address: "server01.domain.com"},
		{ID: "PSMServer_def456", Name: "PSM Server DR", Address: "10.10.10.21"},
	}

	og := buildFullPlatformGraph(nil, nil, nil, psmServers, nil, nil)

	edges := externalEdgesByKind(og, "CyberArk_PSMServerHostedOn")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArk_PSMServerHostedOn edges, got %d", len(edges))
	}

	// Verify address is uppercased in edge end value
	endValues := map[string]bool{}
	for _, e := range edges {
		endValues[e.End.Value] = true
		if e.End.MatchBy != "name" {
			t.Errorf("expected end match_by=name, got %s", e.End.MatchBy)
		}
		if e.Start.MatchBy != "id" {
			t.Errorf("expected start match_by=id, got %s", e.Start.MatchBy)
		}
	}
	if !endValues["SERVER01.DOMAIN.COM"] {
		t.Error("expected edge end value SERVER01.DOMAIN.COM")
	}
	if !endValues["10.10.10.21"] {
		t.Error("expected edge end value 10.10.10.21")
	}
}

func TestCyberArk_PSMServerHostedOn_EmptyAddress(t *testing.T) {
	psmServers := []models.PSMServer{
		{ID: "PSMServer_abc123", Name: "PSM Server Main", Address: ""},
		{ID: "PSMServer_def456", Name: "PSM Server DR", Address: "10.10.10.21"},
	}

	og := buildFullPlatformGraph(nil, nil, nil, psmServers, nil, nil)

	edges := externalEdgesByKind(og, "CyberArk_PSMServerHostedOn")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_PSMServerHostedOn edge (empty address skipped), got %d", len(edges))
	}
	if edges[0].End.Value != "10.10.10.21" {
		t.Errorf("expected end value 10.10.10.21, got %s", edges[0].End.Value)
	}
}

func TestCyberArk_Instance_RootNodeAndContainment(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	og, _ := BuildOpenGraph(BuildInput{
		Users:    []models.User{{ID: "u1", Username: "alice", Source: "CyberArk"}},
		Groups:   []models.Group{{ID: "g1", GroupName: "Admins"}},
		Safes:    []models.Safe{{SafeName: "TestSafe", SafeUrlId: "TestSafe"}},
		Accounts: []models.Account{{ID: "acc1", UserName: "svc", SafeName: "TestSafe"}},
		PVWATag:  "PVWA",
		LogLevel: "WARNING",
	}, logger)

	instanceID := "CAINSTANCE-PVWA"
	inst, ok := og.Nodes[instanceID]
	if !ok {
		t.Fatalf("expected CyberArk_Instance node %s to exist", instanceID)
	}
	hasKind := false
	for _, k := range inst.Kinds {
		if k == "CyberArk_Instance" {
			hasKind = true
		}
	}
	if !hasKind {
		t.Errorf("expected node %s to carry kind CyberArk_Instance, got %v", instanceID, inst.Kinds)
	}

	contained := map[string]bool{}
	for _, e := range edgesByKind(og, "CyberArk_InstanceContains") {
		if e.Start.Value != instanceID {
			t.Errorf("CyberArk_InstanceContains should start at %s, got %s", instanceID, e.Start.Value)
		}
		contained[e.End.Value] = true
	}

	for _, want := range []string{
		"CAUSER-ALICE-PVWA",
		"CAGROUP-ADMINS-PVWA",
		"CASAFE-TESTSAFE-PVWA",
	} {
		if !contained[want] {
			t.Errorf("expected CyberArk_InstanceContains edge to %s", want)
		}
	}

	// Accounts must NOT be directly contained — they nest under their safe.
	if contained["CAACCOUNT-ACC1-PVWA"] {
		t.Errorf("account should not be directly contained by the instance; it nests under its safe")
	}
}

// --- CCP / Application (AppID) tradecraft tests ---
// Tradecraft reference: Marat Nigmatullin (FalconForce), SO-CON 2026 —
// "4 GET requests = 3 Domain admins: CyberArk magic you didn't know about".

// buildWithApplications builds a graph from safes, members, accounts, and applications.
func buildWithApplications(safes []models.Safe, members []models.SafeMember, accounts []models.Account, applications []models.Application) *OpenGraph {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	og, _ := BuildOpenGraph(BuildInput{
		Safes:        safes,
		SafeMembers:  members,
		Accounts:     accounts,
		PVWATag:      "PVWA",
		Applications: applications,
		LogLevel:     "WARNING",
	}, logger)
	return og
}

func TestApplication_UnrestrictedFlag(t *testing.T) {
	apps := []models.Application{
		{AppID: "OpenApp"}, // no authentications at all -> unrestricted
		{AppID: "LockedApp", Authentications: []models.ApplicationAuthentication{
			{AuthType: "machineAddress", AuthValue: "10.0.0.5"},
		}},
	}
	og := buildWithApplications(nil, nil, nil, apps)

	open := og.Nodes["CAAPP-OPENAPP-PVWA"]
	if open == nil {
		t.Fatalf("expected application node CAAPP-OPENAPP-PVWA to exist")
	}
	if open.Properties["isUnrestricted"] != true {
		t.Errorf("OpenApp should be unrestricted, got %v", open.Properties["isUnrestricted"])
	}

	locked := og.Nodes["CAAPP-LOCKEDAPP-PVWA"]
	if locked == nil {
		t.Fatalf("expected application node CAAPP-LOCKEDAPP-PVWA to exist")
	}
	if locked.Properties["isUnrestricted"] != false {
		t.Errorf("LockedApp should be restricted, got %v", locked.Properties["isUnrestricted"])
	}
	if locked.Properties["hasMachineRestriction"] != true {
		t.Errorf("LockedApp should have a machine restriction")
	}
}

func TestApplication_DefaultAIMWebService(t *testing.T) {
	apps := []models.Application{{AppID: "AIMWebService"}}
	og := buildWithApplications(nil, nil, nil, apps)
	node := og.Nodes["CAAPP-AIMWEBSERVICE-PVWA"]
	if node == nil {
		t.Fatalf("expected AIMWebService application node")
	}
	if node.Properties["isDefaultCCPApp"] != true {
		t.Errorf("AIMWebService should be flagged as the default CCP app")
	}
}

func TestApplication_CanRetrieveViaCCP_Edge(t *testing.T) {
	safes := []models.Safe{{SafeName: "Prod", SafeUrlId: "Prod"}}
	accounts := []models.Account{{ID: "acc1", UserName: "domainadmin", SafeName: "Prod"}}
	members := []models.SafeMember{{
		MemberName: "CIApp", MemberType: "Application", SafeName: "Prod",
		Permissions: map[string]interface{}{"retrieveAccounts": true, "listAccounts": true},
	}}
	apps := []models.Application{{AppID: "CIApp"}} // unrestricted

	og := buildWithApplications(safes, members, accounts, apps)
	edges := edgesByKind(og, "CyberArk_CanRetrieveViaCCP")
	if len(edges) != 1 {
		t.Fatalf("expected 1 CyberArk_CanRetrieveViaCCP edge, got %d", len(edges))
	}
	e := edges[0]
	if e.Start.Value != "CAAPP-CIAPP-PVWA" || e.End.Value != "CAACCOUNT-ACC1-PVWA" {
		t.Errorf("unexpected edge endpoints: %s -> %s", e.Start.Value, e.End.Value)
	}
	if e.Props["canRetrievePassword"] != true {
		t.Errorf("expected canRetrievePassword=true")
	}
	if e.Props["appIsUnrestricted"] != true {
		t.Errorf("expected appIsUnrestricted=true for an AppID with no auth restrictions")
	}
}

func TestApplication_NoAccessNoEdge(t *testing.T) {
	safes := []models.Safe{{SafeName: "Prod", SafeUrlId: "Prod"}}
	accounts := []models.Account{{ID: "acc1", UserName: "svc", SafeName: "Prod"}}
	// Application is a member but only has listAccounts (cannot retrieve/use).
	members := []models.SafeMember{{
		MemberName: "ReadOnlyApp", MemberType: "Application", SafeName: "Prod",
		Permissions: map[string]interface{}{"listAccounts": true},
	}}
	apps := []models.Application{{AppID: "ReadOnlyApp"}}

	og := buildWithApplications(safes, members, accounts, apps)
	if edges := edgesByKind(og, "CyberArk_CanRetrieveViaCCP"); len(edges) != 0 {
		t.Errorf("expected no CCP edges for an application without use/retrieve, got %d", len(edges))
	}
}

func TestApplication_MemberTypeFallbackNodeCreated(t *testing.T) {
	// Application appears as a safe member but was not in the Applications list.
	safes := []models.Safe{{SafeName: "Prod", SafeUrlId: "Prod"}}
	accounts := []models.Account{{ID: "acc1", UserName: "svc", SafeName: "Prod"}}
	members := []models.SafeMember{{
		MemberName: "GhostApp", MemberType: "Application", SafeName: "Prod",
		Permissions: map[string]interface{}{"useAccounts": true},
	}}

	og := buildWithApplications(safes, members, accounts, nil)
	if og.Nodes["CAAPP-GHOSTAPP-PVWA"] == nil {
		t.Fatalf("expected a fallback CyberArk_Application node for an application safe member")
	}
	if edges := edgesByKind(og, "CyberArk_CanRetrieveViaCCP"); len(edges) != 1 {
		t.Errorf("expected 1 CCP edge from fallback application node, got %d", len(edges))
	}
}

func TestPlatform_AllowedSafesWildcard(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	platforms := []models.Platform{
		{
			General:               models.PlatformGeneral{ID: "WildPlat", Name: "WildPlat"},
			CredentialsManagement: models.PlatformCredentialsManagement{AllowedSafes: ".*"},
		},
		{
			General:               models.PlatformGeneral{ID: "TightPlat", Name: "TightPlat"},
			CredentialsManagement: models.PlatformCredentialsManagement{AllowedSafes: "^Prod.*$"},
		},
	}

	og, _ := BuildOpenGraph(BuildInput{
		PVWATag:   "PVWA",
		Platforms: platforms,
		LogLevel:  "WARNING",
	}, logger)

	wild := og.Nodes["CAPLATFORM-WILDPLAT-PVWA"]
	if wild == nil || wild.Properties["allowedSafesIsWildcard"] != true {
		t.Errorf("WildPlat (AllowedSafes=.*) should be flagged allowedSafesIsWildcard=true, got %v", wild.Properties["allowedSafesIsWildcard"])
	}
	tight := og.Nodes["CAPLATFORM-TIGHTPLAT-PVWA"]
	if tight == nil || tight.Properties["allowedSafesIsWildcard"] != false {
		t.Errorf("TightPlat should not be flagged as wildcard")
	}
}

func TestApplication_CCPAllowedFrom_Edge(t *testing.T) {
	apps := []models.Application{
		{AppID: "MachineOnlyApp", Authentications: []models.ApplicationAuthentication{
			{AuthType: "machineAddress", AuthValue: "runner1.corp.local"},
		}},
		{AppID: "MachinePlusHashApp", Authentications: []models.ApplicationAuthentication{
			{AuthType: "machineAddress", AuthValue: "runner2.corp.local"},
			{AuthType: "hash", AuthValue: "abc123"},
		}},
	}
	og := buildWithApplications(nil, nil, nil, apps)

	edges := externalEdgesByKind(og, "CyberArk_CCPAllowedFrom")
	if len(edges) != 2 {
		t.Fatalf("expected 2 CyberArk_CCPAllowedFrom edges, got %d", len(edges))
	}

	byTarget := map[string]*Edge{}
	for _, e := range edges {
		byTarget[e.End.Value] = e
	}
	only := byTarget["RUNNER1.CORP.LOCAL"]
	if only == nil || only.Props["machineIsOnlyRestriction"] != true {
		t.Errorf("MachineOnlyApp host should have machineIsOnlyRestriction=true, got %v", only)
	}
	if only != nil && only.Props["targetIsIP"] != false {
		t.Errorf("hostname target should have targetIsIP=false")
	}
	plus := byTarget["RUNNER2.CORP.LOCAL"]
	if plus == nil || plus.Props["machineIsOnlyRestriction"] != false {
		t.Errorf("MachinePlusHashApp host should have machineIsOnlyRestriction=false (hash also required)")
	}
}

func TestApplication_CCPAllowedFrom_IPDetection(t *testing.T) {
	apps := []models.Application{
		{AppID: "IPApp", Authentications: []models.ApplicationAuthentication{
			{AuthType: "machineAddress", AuthValue: "10.0.0.7"},
		}},
	}
	og := buildWithApplications(nil, nil, nil, apps)
	edges := externalEdgesByKind(og, "CyberArk_CCPAllowedFrom")
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Props["targetIsIP"] != true {
		t.Errorf("IP literal should set targetIsIP=true, got %v", edges[0].Props["targetIsIP"])
	}
}
