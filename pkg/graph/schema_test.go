package graph

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jazofra/CyberArkHound/pkg/models"
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

func TestNodeInfoMapKeysAreCanonical(t *testing.T) {
	want := toSet(NodeKinds)
	for kind := range NodeInfoMap {
		if !want[kind] {
			t.Errorf("NodeInfoMap has documentation for %q which is not in graph.NodeKinds (typo or removed node?)", kind)
		}
	}
}

// TestEveryKindHasEntityInfo ensures each canonical node and edge kind ships a
// non-empty Entity Panel info block, so a newly added kind cannot silently reach
// users without curated context.
func TestEveryKindHasEntityInfo(t *testing.T) {
	for _, kind := range NodeKinds {
		if len(NodeInfoSections(kind)) == 0 {
			t.Errorf("node kind %q has no Entity Panel info sections (add it to NodeInfoMap)", kind)
		}
	}
	for _, kind := range EdgeKinds {
		if len(EdgeInfoSections(kind)) == 0 {
			t.Errorf("edge kind %q has no Entity Panel info sections (add it to EdgeInfoMap)", kind)
		}
	}
}

// TestSchemaJSONInfoInSync is the drift guard for the generated Entity Panel
// content: extension/schema.json must equal the output of graph.BuildSchemaJSON,
// so the committed schema always reflects NodeInfoMap / EdgeInfoMap. When it
// fails, regenerate with `go generate ./...` (or `go run ./cmd/gen-schema`).
func TestSchemaJSONInfoInSync(t *testing.T) {
	path := filepath.Join("..", "..", "extension", "schema.json")
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	regenerated, err := BuildSchemaJSON(committed)
	if err != nil {
		t.Fatalf("BuildSchemaJSON failed: %v", err)
	}

	if !bytes.Equal(committed, regenerated) {
		t.Errorf("extension/schema.json is out of sync with NodeInfoMap/EdgeInfoMap; run `go generate ./...` to regenerate it")
	}
}

// TestSchemaInfoSectionsAreWellFormed checks that every generated info section
// satisfies the OpenGraph constraints BloodHound enforces: a valid section id, a
// non-empty title, a positive position, and non-empty markdown content.
func TestSchemaInfoSectionsAreWellFormed(t *testing.T) {
	idPattern := regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)
	check := func(kind string, sections map[string]InfoSection) {
		for id, sec := range sections {
			if !idPattern.MatchString(id) {
				t.Errorf("%s: info section id %q does not match ^[a-z0-9_-]{1,128}$", kind, id)
			}
			if sec.Title == "" {
				t.Errorf("%s: info section %q has an empty title", kind, id)
			}
			if sec.Position < 1 {
				t.Errorf("%s: info section %q has non-positive position %d", kind, id, sec.Position)
			}
			if sec.Markdown.Content == "" {
				t.Errorf("%s: info section %q has empty markdown content", kind, id)
			}
		}
	}
	for _, kind := range NodeKinds {
		check(kind, NodeInfoSections(kind))
	}
	for _, kind := range EdgeKinds {
		check(kind, EdgeInfoSections(kind))
	}
}

// TestEdgeTraversabilityCoversCanonicalKinds ensures every canonical edge kind
// has an explicit pathfinding decision, and that no stale or misspelled kind
// lingers in the map.
func TestEdgeTraversabilityCoversCanonicalKinds(t *testing.T) {
	want := toSet(EdgeKinds)
	for _, kind := range EdgeKinds {
		if _, ok := EdgeTraversability[kind]; !ok {
			t.Errorf("edge kind %q has no entry in EdgeTraversability", kind)
		}
	}
	for kind := range EdgeTraversability {
		if !want[kind] {
			t.Errorf("EdgeTraversability has %q which is not in graph.EdgeKinds (typo or removed edge?)", kind)
		}
	}
}

// TestSchemaTraversabilityMatchesGo reports, per kind, any is_traversable flag
// in the committed schema.json that disagrees with EdgeTraversability. The full
// drift guard (TestSchemaJSONInfoInSync) also catches this, but this test names
// the offending kind.
func TestSchemaTraversabilityMatchesGo(t *testing.T) {
	schema := loadSchema(t)
	raw, _ := schema["relationship_kinds"].([]interface{})
	for _, item := range raw {
		m, _ := item.(map[string]interface{})
		name, _ := m["name"].(string)
		got, ok := m["is_traversable"].(bool)
		if !ok {
			t.Errorf("schema.json relationship kind %q has no boolean is_traversable", name)
			continue
		}
		if want := EdgeTraversability[name]; got != want {
			t.Errorf("schema.json %q is_traversable=%v, EdgeTraversability says %v; run `go generate ./...`", name, got, want)
		}
	}
}

// TestPathfindingInvariants pins the decisions that attack-path correctness
// depends on. The core credential chain must stay traversable or BloodHound
// stops finding real paths; LinkedTo points against the direction of control
// and must stay non-traversable or BloodHound reports false paths.
func TestPathfindingInvariants(t *testing.T) {
	mustTraverse := []string{
		"CyberArk_MemberOf",
		"CyberArk_HasAccessTo",
		"CyberArk_CanGrantAccessTo",
		"CyberArk_Contains",
		"CyberArk_CanRetrieveViaCCP",
		"CyberArk_SyncsToUser",
		"CyberArk_SyncsToGroup",
		"CyberArk_SyncsToADUser",
	}
	for _, kind := range mustTraverse {
		if !EdgeTraversability[kind] {
			t.Errorf("%s must be traversable: it is a link in the core credential-access chain", kind)
		}
	}
	mustNotTraverse := []string{
		"CyberArk_LinkedTo",
		"CyberArk_UsedAccount",
		"CyberArk_CanApprove",
		"CyberArk_InstanceContains",
	}
	for _, kind := range mustNotTraverse {
		if EdgeTraversability[kind] {
			t.Errorf("%s must not be traversable: control of the source does not grant the target", kind)
		}
	}
}

// TestEdgeOverviewStatesTraversability checks that each edge's Overview section
// tells the analyst why BloodHound draws the edge solid or dashed.
func TestEdgeOverviewStatesTraversability(t *testing.T) {
	for _, kind := range EdgeKinds {
		overview := EdgeInfoSections(kind)[infoOverview].Markdown.Content
		want := nonTraversableNote
		if EdgeTraversability[kind] {
			want = traversableNote
		}
		if !strings.HasSuffix(overview, "\n\n"+want) {
			t.Errorf("%s overview does not end with its pathfinding note %q", kind, want)
		}
	}
}

// TestBuildSchemaJSONRejectsUndecidedTraversability ensures the generator refuses
// a relationship kind with no traversability decision instead of defaulting it.
func TestBuildSchemaJSONRejectsUndecidedTraversability(t *testing.T) {
	in := []byte(`{"schema":{},"node_kinds":[],"relationship_kinds":[{"name":"CyberArk_NotARealEdge","description":"x","is_traversable":true}],"environments":[],"relationship_findings":[]}`)
	if _, err := BuildSchemaJSON(in); err == nil {
		t.Fatal("expected an error for a relationship kind missing from EdgeTraversability")
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
