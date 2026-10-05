package exporter

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/sirupsen/logrus"
)

type exportedEdge struct {
	Kind  string                 `json:"kind"`
	Start map[string]string      `json:"start"`
	End   map[string]string      `json:"end"`
	Props map[string]interface{} `json:"properties"`
}

type exportedNode struct {
	ID         string                 `json:"id"`
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties"`
}

type exportedDoc struct {
	Metadata struct {
		SourceKind string `json:"source_kind"`
	} `json:"metadata"`
	Graph struct {
		Edges []exportedEdge `json:"edges"`
		Nodes []exportedNode `json:"nodes"`
	} `json:"graph"`
}

func quietLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

func sampleGraph() *graph.OpenGraph {
	og := graph.NewOpenGraph(quietLogger())
	og.MergeNode(&graph.Node{ID: "CAUSER-B-PVWA", Kinds: []string{"CyberArk_User", "CyberArkBase"}, Properties: map[string]interface{}{"name": "b"}})
	og.MergeNode(&graph.Node{ID: "CAUSER-A-PVWA", Kinds: []string{"CyberArk_User", "CyberArkBase"}, Properties: map[string]interface{}{"name": "a"}})
	og.MergeNode(&graph.Node{ID: "CAGROUP-G-PVWA", Kinds: []string{"CyberArk_Group", "CyberArkBase"}, Properties: map[string]interface{}{"name": "g"}})
	og.AddEdge("CyberArk_MemberOf", "CAUSER-B-PVWA", "CAGROUP-G-PVWA", "id", "id", map[string]interface{}{"source": "userDetails"}, false)
	og.AddEdge("CyberArk_MemberOf", "CAUSER-A-PVWA", "CAGROUP-G-PVWA", "id", "id", nil, false)
	og.AddEdge("CyberArk_SyncsToUser", "A@CORP.LOCAL", "CAUSER-A-PVWA", "name", "id", map[string]interface{}{"inferred": true}, true)
	return og
}

func readDoc(t *testing.T, r io.Reader) exportedDoc {
	t.Helper()
	var doc exportedDoc
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	return doc
}

func TestExportRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := ExportToBloodHoundJSON(sampleGraph(), path, quietLogger()); err != nil {
		t.Fatalf("export: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc := readDoc(t, f)

	if doc.Metadata.SourceKind != "CyberArkBase" {
		t.Errorf("source_kind = %q", doc.Metadata.SourceKind)
	}

	var nodeIDs []string
	for _, n := range doc.Graph.Nodes {
		nodeIDs = append(nodeIDs, n.ID)
	}
	if want := []string{"CAGROUP-G-PVWA", "CAUSER-A-PVWA", "CAUSER-B-PVWA"}; !reflect.DeepEqual(nodeIDs, want) {
		t.Errorf("nodes = %v, want sorted %v", nodeIDs, want)
	}

	if len(doc.Graph.Edges) != 3 {
		t.Fatalf("edges = %d, want 3 (internal + external)", len(doc.Graph.Edges))
	}
	// Internal edges come first, sorted by start; external edges follow.
	if got := doc.Graph.Edges[0].Start["value"]; got != "CAUSER-A-PVWA" {
		t.Errorf("first edge starts at %s, want CAUSER-A-PVWA", got)
	}
	if doc.Graph.Edges[0].Props != nil {
		t.Errorf("edge without properties should omit them, got %v", doc.Graph.Edges[0].Props)
	}
	if got := doc.Graph.Edges[1].Props["source"]; got != "userDetails" {
		t.Errorf("edge properties not exported: %v", doc.Graph.Edges[1].Props)
	}
	ext := doc.Graph.Edges[2]
	if ext.Kind != "CyberArk_SyncsToUser" || ext.Start["match_by"] != "name" || ext.End["match_by"] != "id" {
		t.Errorf("external edge exported incorrectly: %+v", ext)
	}

	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("export mode = %o, want 600", perm)
		}
	}
}

func TestExportEmptyGraphIsValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := ExportToBloodHoundJSON(graph.NewOpenGraph(quietLogger()), path, quietLogger()); err != nil {
		t.Fatalf("export: %v", err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	doc := readDoc(t, f)
	if len(doc.Graph.Nodes) != 0 || len(doc.Graph.Edges) != 0 {
		t.Fatalf("expected an empty graph, got %+v", doc.Graph)
	}
}

func TestExportIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := ExportToBloodHoundJSON(sampleGraph(), a, quietLogger()); err != nil {
		t.Fatal(err)
	}
	if err := ExportToBloodHoundJSON(sampleGraph(), b, quietLogger()); err != nil {
		t.Fatal(err)
	}
	da, _ := os.ReadFile(a)
	db, _ := os.ReadFile(b)
	if string(da) != string(db) {
		t.Fatal("two exports of the same graph differ")
	}
}

func TestExportZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cyberark_export.zip")
	if err := ExportToBloodHoundJSON(sampleGraph(), path, quietLogger()); err != nil {
		t.Fatalf("export: %v", err)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("not a zip archive: %v", err)
	}
	defer zr.Close()
	if len(zr.File) != 1 || zr.File[0].Name != "cyberark_export.json" {
		t.Fatalf("zip entries = %v, want [cyberark_export.json]", zr.File)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	doc := readDoc(t, rc)
	if len(doc.Graph.Nodes) != 3 || len(doc.Graph.Edges) != 3 {
		t.Fatalf("zip entry has %d nodes, %d edges", len(doc.Graph.Nodes), len(doc.Graph.Edges))
	}
}

func TestExportToMissingDirectoryFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "out.json")
	if err := ExportToBloodHoundJSON(sampleGraph(), path, quietLogger()); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func TestEdgeLessTieBreaksOnProperties(t *testing.T) {
	a := &graph.Edge{Kind: "K", Start: graph.EdgeRef{Value: "S"}, End: graph.EdgeRef{Value: "E"}, Props: map[string]interface{}{"x": 1}}
	b := &graph.Edge{Kind: "K", Start: graph.EdgeRef{Value: "S"}, End: graph.EdgeRef{Value: "E"}, Props: map[string]interface{}{"x": 2}}
	if !edgeLess(a, b) || edgeLess(b, a) {
		t.Fatal("edges differing only in properties must be ordered by them")
	}
}

func TestIsZipPath(t *testing.T) {
	for path, want := range map[string]bool{"out.zip": true, "OUT.ZIP": true, "out.json": false, "zip": false} {
		if got := IsZipPath(path); got != want {
			t.Errorf("IsZipPath(%q) = %v, want %v", path, got, want)
		}
	}
}
