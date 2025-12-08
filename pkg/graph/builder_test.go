package graph

import (
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

func TestBuildOpenGraph(t *testing.T) {
	// Setup logger (discard output)
	logger := logrus.New()
	logger.SetOutput(new(NullWriter))

	// Mock data
	users := []models.User{
		{
			ID:       1,
			Username: "jdoe",
			Source:   "CyberArk",
			PersonalDetails: models.PersonalDetails{
				FirstName: "John",
				LastName:  "Doe",
			},
			GroupsMembership: []models.UserGroupMembership{
				{GroupName: "Admins"},
			},
		},
	}

	groups := []models.Group{
		{
			ID:        100,
			GroupName: "Admins",
			GroupType: "CyberArk",
		},
	}

	safes := []models.Safe{
		{
			SafeName:    "TestSafe",
			SafeUrlId:   "TestSafe",
			Description: "A test safe",
		},
	}

	accounts := []models.Account{
		{
			ID:       "acc1",
			UserName: "root",
			Address:  "server1.local",
			SafeName: "TestSafe",
		},
	}

	safeMembers := []models.SafeMember{
		{
			MemberName: "jdoe",
			MemberType: "User",
			SafeName:   "TestSafe",
			Permissions: map[string]interface{}{
				"UseAccounts":      true,
				"RetrieveAccounts": true,
			},
		},
	}

	targetDomains := []string{"local"}

	// Build graph
	og, err := BuildOpenGraph(
		users,
		groups,
		safes,
		safeMembers,
		accounts,
		targetDomains,
		nil, // no activity
		logger,
		false,
		"INFO",
	)

	if err != nil {
		t.Fatalf("BuildOpenGraph failed: %v", err)
	}

	// Assertions

	// Check Node counts
	expectedNodeCount := 4 // 1 user, 1 group, 1 safe, 1 account
	if len(og.Nodes) != expectedNodeCount {
		t.Errorf("Expected %d nodes, got %d", expectedNodeCount, len(og.Nodes))
	}

	// Check specific nodes exist
	if _, ok := og.Nodes["causer-jdoe"]; !ok {
		t.Error("Node causer-jdoe missing")
	}
	if _, ok := og.Nodes["cagroup-Admins"]; !ok {
		t.Error("Node cagroup-Admins missing")
	}
	if _, ok := og.Nodes["casafe-TestSafe"]; !ok {
		t.Error("Node casafe-TestSafe missing")
	}
	if _, ok := og.Nodes["caaccount-acc1"]; !ok {
		t.Error("Node caaccount-acc1 missing")
	}

	// Check Edges
	// 1. User -> Group (MemberOf)
	// 2. Safe -> Account (Contains)
	// 3. User -> Account (HasAccessTo) - derived from safe permissions
	// 4. Account -> ADUser (SyncsToADUser) - derived from address matching target domain (server1.local matches "local" domain?)
	//    Wait, logic is: if addressLower == domainLower. "server1.local" != "local". So no sync edge.

	hasMemberOf := false
	hasContains := false
	hasAccessTo := false

	for _, edge := range og.InternalEdges {
		if edge.Kind == "CyberArkMemberOf" &&
		   edge.Start.Value == "causer-jdoe" &&
		   edge.End.Value == "cagroup-Admins" {
			hasMemberOf = true
		}
		if edge.Kind == "CyberArkContains" &&
		   edge.Start.Value == "casafe-TestSafe" &&
		   edge.End.Value == "caaccount-acc1" {
			hasContains = true
		}
		if edge.Kind == "CyberArkHasAccessTo" &&
		   edge.Start.Value == "causer-jdoe" &&
		   edge.End.Value == "caaccount-acc1" {
			hasAccessTo = true
		}
	}

	if !hasMemberOf {
		t.Error("Missing CyberArkMemberOf edge (jdoe -> Admins)")
	}
	if !hasContains {
		t.Error("Missing CyberArkContains edge (TestSafe -> acc1)")
	}
	if !hasAccessTo {
		t.Error("Missing CyberArkHasAccessTo edge (jdoe -> acc1)")
	}
}

// NullWriter implements io.Writer and discards all data
type NullWriter struct{}

func (nw *NullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
