package graph

import (
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

func findingByID(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestComputeFindings_UnrestrictedAppAndCCPRetrieval(t *testing.T) {
	safes := []models.Safe{{SafeName: "Prod", SafeUrlId: "Prod"}} // no managingCPM
	accounts := []models.Account{{ID: "acc1", UserName: "domainadmin", SafeName: "Prod"}}
	members := []models.SafeMember{{
		MemberName: "AIMWebService", MemberType: "Application", SafeName: "Prod",
		Permissions: map[string]interface{}{"retrieveAccounts": true},
	}}
	apps := []models.Application{{AppID: "AIMWebService"}} // default + unrestricted

	og := buildWithApplications(safes, members, accounts, apps)
	fs := ComputeFindings(og)

	if findingByID(fs, "CCP_UNRESTRICTED_APP") == nil {
		t.Errorf("expected CCP_UNRESTRICTED_APP finding")
	}
	if findingByID(fs, "CCP_DEFAULT_AIMWEBSERVICE") == nil {
		t.Errorf("expected CCP_DEFAULT_AIMWEBSERVICE finding")
	}
	if f := findingByID(fs, "CCP_UNRESTRICTED_RETRIEVAL"); f == nil || f.Count != 1 {
		t.Errorf("expected CCP_UNRESTRICTED_RETRIEVAL count=1, got %v", f)
	}
	if f := findingByID(fs, "SAFE_NO_CPM"); f == nil || f.Count != 1 {
		t.Errorf("expected SAFE_NO_CPM count=1, got %v", f)
	}

	// Findings must be ordered by severity (Critical first).
	if len(fs) >= 2 && severityRank(fs[0].Severity) > severityRank(fs[len(fs)-1].Severity) {
		t.Errorf("findings not ordered by severity: %+v", fs)
	}
}

func TestComputeFindings_CleanEnvironment(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	og, _ := BuildOpenGraph(BuildInput{
		Safes:    []models.Safe{{SafeName: "Prod", SafeUrlId: "Prod", ManagingCPM: "PasswordManager"}},
		PVWATag:  "PVWA",
		LogLevel: "WARNING",
	}, logger)

	if fs := ComputeFindings(og); len(fs) != 0 {
		t.Errorf("expected no findings for a clean environment, got %+v", fs)
	}
}

func TestComputeFindings_ReconcileHijackAndPSMBreakout(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	platforms := []models.Platform{{
		General: models.PlatformGeneral{ID: "WinDomain", Name: "WinDomain"},
		SessionManagement: models.PlatformSessionManagement{
			PSMServerID: "PSM1",
			RequirePrivilegedSessionMonitoringAndIsolation: false,
			RecordAndSaveSessionActivity:                   false,
		},
	}}
	safes := []models.Safe{
		{SafeName: "Prod", SafeUrlId: "Prod", ManagingCPM: "PasswordManager"},
		{SafeName: "Admin", SafeUrlId: "Admin", ManagingCPM: "PasswordManager"},
	}
	accounts := []models.Account{
		{ID: "acc1", UserName: "svc", SafeName: "Prod", PlatformID: "WinDomain"},
		{ID: "recon1", UserName: "da-reconcile", SafeName: "Admin", PlatformID: "WinDomain"},
	}
	members := []models.SafeMember{{
		MemberName: "attacker", MemberType: "user", SafeName: "Prod",
		Permissions: map[string]interface{}{"addAccounts": true},
	}}
	linked := map[string][]models.LinkedAccount{
		"acc1": {{Name: "reconcile", AccountID: "recon1", SafeName: "Admin", ExtraPassID: 3}},
	}

	og, _ := BuildOpenGraph(BuildInput{
		Safes:          safes,
		SafeMembers:    members,
		Accounts:       accounts,
		PVWATag:        "PVWA",
		Platforms:      platforms,
		LinkedAccounts: linked,
		LogLevel:       "WARNING",
	}, logger)

	fs := ComputeFindings(og)
	if f := findingByID(fs, "RECONCILE_HIJACK_EXPOSURE"); f == nil || f.Count != 1 {
		t.Errorf("expected RECONCILE_HIJACK_EXPOSURE count=1, got %v", f)
	}
	// acc1 and recon1 both use the PSM-routed, unmonitored platform.
	if f := findingByID(fs, "PSM_BREAKOUT_EXPOSURE"); f == nil || f.Count != 2 {
		t.Errorf("expected PSM_BREAKOUT_EXPOSURE count=2, got %v", f)
	}
}
