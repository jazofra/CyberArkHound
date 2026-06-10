package graph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
)

// These drift-guard tests keep the hand-maintained extension/schema.json,
// cyberark_model.json, and EdgeInfoMap in sync with the canonical NodeKinds /
// EdgeKinds lists. When a new node or edge kind is added in builder.go (and to
// kinds.go), these tests fail until the schema, model, and edge metadata are
// updated — catching the exact omission that is easy to make by hand.

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, i := range items {
		s[i] = true
	}
	return s
}

func loadSchema(t *testing.T) map[string]interface{} {
	t.Helper()
	path := filepath.Join("..", "..", "extension", "schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	return schema
}

func schemaKindNames(t *testing.T, schema map[string]interface{}, key string) map[string]bool {
	t.Helper()
	raw, ok := schema[key].([]interface{})
	if !ok {
		t.Fatalf("schema.json missing or malformed %q", key)
	}
	names := make(map[string]bool, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("schema.json %q contains a non-object entry", key)
		}
		name, _ := m["name"].(string)
		if name == "" {
			t.Fatalf("schema.json %q contains an entry with no name", key)
		}
		names[name] = true
	}
	return names
}

func TestSchemaNodeKindsMatchCanonical(t *testing.T) {
	schema := loadSchema(t)
	got := schemaKindNames(t, schema, "node_kinds")
	want := toSet(NodeKinds)

	for k := range want {
		if !got[k] {
			t.Errorf("schema.json node_kinds is missing canonical node kind %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("schema.json node_kinds has %q which is not in graph.NodeKinds", k)
		}
	}
}

func TestSchemaRelationshipKindsMatchCanonical(t *testing.T) {
	schema := loadSchema(t)
	got := schemaKindNames(t, schema, "relationship_kinds")
	want := toSet(EdgeKinds)

	for k := range want {
		if !got[k] {
			t.Errorf("schema.json relationship_kinds is missing canonical edge kind %q", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("schema.json relationship_kinds has %q which is not in graph.EdgeKinds", k)
		}
	}
}

func TestEdgeInfoMapKeysAreCanonical(t *testing.T) {
	want := toSet(EdgeKinds)
	for kind := range EdgeInfoMap {
		if !want[kind] {
			t.Errorf("EdgeInfoMap has documentation for %q which is not in graph.EdgeKinds (typo or removed edge?)", kind)
		}
	}
}

func TestCustomModelTypesAreCanonicalNodeKinds(t *testing.T) {
	path := filepath.Join("..", "..", "cyberark_model.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	var model struct {
		CustomTypes map[string]json.RawMessage `json:"custom_types"`
	}
	if err := json.Unmarshal(data, &model); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}

	want := toSet(NodeKinds)
	for kind := range model.CustomTypes {
		if !want[kind] {
			t.Errorf("cyberark_model.json custom_types has %q which is not in graph.NodeKinds", kind)
		}
	}
}

// TestEmittedEdgeKindsAreCanonical builds a small graph exercising several edge
// kinds and asserts every emitted kind is registered in graph.EdgeKinds. This
// catches an edge that is emitted by the builder but never added to the
// canonical list (and therefore never validated against the schema).
func TestEmittedEdgeKindsAreCanonical(t *testing.T) {
	want := toSet(EdgeKinds)
	checkEmitted := func(og *OpenGraph) {
		for _, e := range og.InternalEdges {
			if !want[e.Kind] {
				t.Errorf("builder emitted internal edge kind %q not present in graph.EdgeKinds", e.Kind)
			}
		}
		for _, e := range og.ExternalEdges {
			if !want[e.Kind] {
				t.Errorf("builder emitted external edge kind %q not present in graph.EdgeKinds", e.Kind)
			}
		}
	}

	// A graph touching applications/CCP, safes, accounts, and instance edges.
	safes := []models.Safe{{SafeName: "Prod", SafeUrlId: "Prod", ManagingCPM: "PasswordManager"}}
	accounts := []models.Account{{ID: "acc1", UserName: "domainadmin", SafeName: "Prod"}}
	members := []models.SafeMember{{
		MemberName: "CIApp", MemberType: "Application", SafeName: "Prod",
		Permissions: map[string]interface{}{"retrieveAccounts": true},
	}}
	apps := []models.Application{{AppID: "CIApp", Authentications: []models.ApplicationAuthentication{
		{AuthType: "machineAddress", AuthValue: "runner1.corp.local"},
	}}}
	checkEmitted(buildWithApplications(safes, members, accounts, apps))
}
