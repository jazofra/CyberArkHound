package graph

import (
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

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
