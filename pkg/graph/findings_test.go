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
