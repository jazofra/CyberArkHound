// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The types below mirror the on-disk layout of extension/schema.json exactly,
// with struct field order fixed so re-marshaling is deterministic. They exist so
// the curated Entity Panel "info" sections (NodeInfoMap / EdgeInfoMap) can be the
// single source of truth: BuildSchemaJSON round-trips the committed schema
// through these types and injects the info blocks, and a drift-guard test keeps
// the committed file in lockstep with the Go maps. Every field present in
// schema.json must be represented here, or a round-trip would silently drop it.

// SchemaFile is the top-level OpenGraph extension definition.
type SchemaFile struct {
	Schema               SchemaHeader      `json:"schema"`
	NodeKinds            []SchemaNodeKind  `json:"node_kinds"`
	RelationshipKinds    []SchemaRelKind   `json:"relationship_kinds"`
	Environments         []SchemaEnv       `json:"environments"`
	RelationshipFindings []json.RawMessage `json:"relationship_findings"`
}

// SchemaHeader is the extension's identifying metadata.
type SchemaHeader struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
	Namespace   string `json:"namespace"`
}

// SchemaNodeKind is one entry in node_kinds, including its Entity Panel info.
type SchemaNodeKind struct {
	Name          string                 `json:"name"`
	DisplayName   string                 `json:"display_name"`
	Description   string                 `json:"description"`
	IsDisplayKind bool                   `json:"is_display_kind"`
	Icon          string                 `json:"icon"`
	Color         string                 `json:"color"`
	Info          map[string]InfoSection `json:"info,omitempty"`
}

// SchemaRelKind is one entry in relationship_kinds, including its Entity Panel info.
type SchemaRelKind struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	IsTraversable bool                   `json:"is_traversable"`
	Info          map[string]InfoSection `json:"info,omitempty"`
}

// SchemaEnv is one entry in environments.
type SchemaEnv struct {
	EnvironmentKind string   `json:"environment_kind"`
	SourceKind      string   `json:"source_kind"`
	PrincipalKinds  []string `json:"principal_kinds"`
}

// BuildSchemaJSON parses the committed schema.json, overwrites the "info" block
// on every node and relationship kind from the curated NodeInfoMap / EdgeInfoMap,
// and re-marshals it. All other fields are preserved verbatim. The output is
// indent-formatted with a trailing newline and HTML escaping disabled so URLs
// and angle-bracket placeholders (e.g. <pvwa>) render literally.
func BuildSchemaJSON(existing []byte) ([]byte, error) {
	var sf SchemaFile
	if err := json.Unmarshal(existing, &sf); err != nil {
		return nil, fmt.Errorf("parse schema.json: %w", err)
	}

	for i := range sf.NodeKinds {
		sf.NodeKinds[i].Info = NodeInfoSections(sf.NodeKinds[i].Name)
	}
	for i := range sf.RelationshipKinds {
		sf.RelationshipKinds[i].Info = EdgeInfoSections(sf.RelationshipKinds[i].Name)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&sf); err != nil {
		return nil, fmt.Errorf("marshal schema.json: %w", err)
	}
	return buf.Bytes(), nil
}
