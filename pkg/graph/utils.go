// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Node represents a BloodHound node
type Node struct {
	ID         string                 `json:"id"`
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties"`
}

// Edge represents a BloodHound edge
type Edge struct {
	Kind  string                 `json:"kind"`
	Start EdgeRef                `json:"start"`
	End   EdgeRef                `json:"end"`
	Props map[string]interface{} `json:"properties,omitempty"`
}

// EdgeRef represents a node reference in an edge
type EdgeRef struct {
	Value   string `json:"value"`
	MatchBy string `json:"match_by"`
}

// OpenGraph represents the complete graph structure
type OpenGraph struct {
	Nodes         map[string]*Node
	InternalEdges []*Edge
	ExternalEdges []*Edge
	EdgeSet       map[string]bool
	Logger        *logrus.Logger
}

// NewOpenGraph creates a new OpenGraph
func NewOpenGraph(logger *logrus.Logger) *OpenGraph {
	return &OpenGraph{
		Nodes:         make(map[string]*Node),
		InternalEdges: make([]*Edge, 0),
		ExternalEdges: make([]*Edge, 0),
		EdgeSet:       make(map[string]bool),
		Logger:        logger,
	}
}

// MergeNode adds or merges a node into the graph
func (og *OpenGraph) MergeNode(node *Node) {
	existing, exists := og.Nodes[node.ID]
	if !exists {
		og.Nodes[node.ID] = node
		return
	}

	// Merge kinds
	kindSet := make(map[string]bool)
	for _, k := range existing.Kinds {
		kindSet[k] = true
	}
	for _, k := range node.Kinds {
		if !kindSet[k] {
			existing.Kinds = append(existing.Kinds, k)
		}
	}

	// Merge properties
	for k, v := range node.Properties {
		if _, exists := existing.Properties[k]; !exists {
			existing.Properties[k] = v
		}
	}
}

// AddEdge adds an edge to the graph (with deduplication)
func (og *OpenGraph) AddEdge(kind, startID, endID, startMatchBy, endMatchBy string, props map[string]interface{}, external bool) {
	// Create unique key for deduplication
	propsJSON, _ := json.Marshal(props)
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", kind, startID, endID, startMatchBy, endMatchBy, string(propsJSON))

	if og.EdgeSet[key] {
		return
	}
	og.EdgeSet[key] = true

	edge := &Edge{
		Kind: kind,
		Start: EdgeRef{
			Value:   startID,
			MatchBy: startMatchBy,
		},
		End: EdgeRef{
			Value:   endID,
			MatchBy: endMatchBy,
		},
		Props: props,
	}

	if external {
		og.ExternalEdges = append(og.ExternalEdges, edge)
	} else {
		og.InternalEdges = append(og.InternalEdges, edge)
	}
}

// ParseDomainFromDN extracts domain from distinguished name
func ParseDomainFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	re := regexp.MustCompile(`(?i)DC=([^,]+)`)
	matches := re.FindAllStringSubmatch(dn, -1)
	if len(matches) == 0 {
		return ""
	}

	parts := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			parts = append(parts, match[1])
		}
	}

	return strings.ToLower(strings.Join(parts, "."))
}

// ParseSAMAccountNameFromDN attempts to derive a sAMAccountName-like identifier from a DN.
//
// In some environments, the CN RDN is formatted like: "Lastname Firstname gid" where the last
// whitespace-separated token is the user's GID/sAMAccountName (e.g. "CN=Ortiz Jon z0052twm,...").
// If no suitable token can be derived, it returns an empty string.
func ParseSAMAccountNameFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	// Extract CN value from the RDN (best-effort; does not fully handle escaped commas).
	re := regexp.MustCompile(`(?i)(?:^|,)\s*CN=([^,]+)`)
	match := re.FindStringSubmatch(dn)
	if len(match) < 2 {
		return ""
	}

	cn := strings.TrimSpace(match[1])
	if cn == "" {
		return ""
	}

	parts := strings.Fields(cn)
	if len(parts) == 0 {
		return ""
	}

	candidate := strings.TrimSpace(parts[len(parts)-1])
	if candidate == "" || strings.Contains(candidate, "@") {
		return ""
	}

	// Keep it conservative: alphanumerics plus common account separators.
	valid := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	if !valid.MatchString(candidate) {
		return ""
	}

	return candidate
}

// NormPermName normalizes permission name
func NormPermName(p string) string {
	if p == "" {
		return ""
	}
	// Remove all non-alphanumeric characters and convert to lowercase
	var result strings.Builder
	for _, ch := range strings.ToLower(p) {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

// StripAfterAt returns the part of s before '@' (if present), after trimming spaces.
// If '@' is the first character, it returns the trimmed input unchanged.
func StripAfterAt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if idx := strings.IndexByte(s, '@'); idx > 0 {
		return s[:idx]
	}
	return s
}

// StripAfterDot returns the part of s before '.' (if present), after trimming spaces.
// If '.' is the first character, it returns the trimmed input unchanged.
func StripAfterDot(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if idx := strings.IndexByte(s, '.'); idx > 0 {
		return s[:idx]
	}
	return s
}

// SanitizeProperties removes nil values and serializes complex objects for BloodHound
func SanitizeProperties(props map[string]interface{}) map[string]interface{} {
	complexProperties := map[string]bool{
		"safePermissions":             true,
		"authorizedInterfaces":        true,
		"vaultAuthorization":          true,
		"permissions":                 true,
		"matchedPermissionNames":      true,
		"matchedPermissionParameters": true,
	}

	sanitized := make(map[string]interface{})

	for key, value := range props {
		if value == nil {
			continue
		}

		// Check if this is a complex property that needs serialization
		if complexProperties[key] {
			jsonBytes, err := json.Marshal(value)
			if err == nil {
				sanitized[key] = string(jsonBytes)
			}
			continue
		}

		// Handle different types
		switch v := value.(type) {
		case string, int, float64, bool, int64, int32:
			sanitized[key] = value
		case []interface{}:
			if len(v) == 0 {
				continue
			}
			// Check if it's a primitive slice
			if len(v) > 0 {
				switch v[0].(type) {
				case string, int, float64, bool, int64, int32:
					sanitized[key] = value
				default:
					// Complex slice, serialize it
					jsonBytes, err := json.Marshal(value)
					if err == nil {
						sanitized[key] = string(jsonBytes)
					}
				}
			}
		default:
			// Complex type, serialize it
			jsonBytes, err := json.Marshal(value)
			if err == nil {
				sanitized[key] = string(jsonBytes)
			}
		}
	}

	return sanitized
}

// UnixToISO8601 converts Unix timestamp to ISO 8601 string
func UnixToISO8601(timestamp float64) string {
	t := time.Unix(int64(timestamp), 0)
	return t.UTC().Format(time.RFC3339)
}

// GetSummary returns statistics about the graph
func (og *OpenGraph) GetSummary() map[string]interface{} {
	// Count nodes by kind
	nodeCounts := make(map[string]int)
	for _, node := range og.Nodes {
		for _, kind := range node.Kinds {
			nodeCounts[kind]++
		}
	}

	// Count edges by kind
	internalEdgeCounts := make(map[string]int)
	for _, edge := range og.InternalEdges {
		internalEdgeCounts[edge.Kind]++
	}

	externalEdgeCounts := make(map[string]int)
	for _, edge := range og.ExternalEdges {
		externalEdgeCounts[edge.Kind]++
	}

	return map[string]interface{}{
		"total_nodes":            len(og.Nodes),
		"nodes_by_kind":          nodeCounts,
		"total_internal_edges":   len(og.InternalEdges),
		"internal_edges_by_kind": internalEdgeCounts,
		"total_external_edges":   len(og.ExternalEdges),
		"external_edges_by_kind": externalEdgeCounts,
	}
}

// Account access permissions that allow direct credential access
var AccountAccessPermissions = map[string]bool{
	"useaccounts":      true, // Use accounts via PSM without viewing passwords
	"retrieveaccounts": true, // Retrieve and view passwords
}

// Escalation permissions that allow modifying safe to grant access
var EscalationPermissions = map[string]bool{
	"managesafe":        true, // Update safe properties, recover, delete
	"managesafemembers": true, // Add/remove members, modify permissions
}

// Dual control permissions that govern approval workflows
var DualControlPermissions = map[string]bool{
	"accesswithoutconfirmation":    true, // Can bypass dual control approval
	"requestsauthorizationlevel1": true, // Can approve L1 access requests
	"requestsauthorizationlevel2": true, // Can approve L2 access requests
}
