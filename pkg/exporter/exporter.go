// Package exporter provides functions to export CyberArk OpenGraph data
// to BloodHound-compatible JSON format with progress logging.
package exporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/sirupsen/logrus"
)

// edgeSortKey produces a stable ordering key for an edge so that exports are
// deterministic across runs (two collections of the same environment diff cleanly).
func edgeSortKey(e *graph.Edge) string {
	propsJSON, _ := json.Marshal(e.Props)
	return strings.Join([]string{e.Kind, e.Start.Value, e.End.Value, string(propsJSON)}, "|")
}

// sortedNodes returns the graph's nodes ordered by ID for deterministic output.
func sortedNodes(og *graph.OpenGraph) []*graph.Node {
	nodes := make([]*graph.Node, 0, len(og.Nodes))
	for _, n := range og.Nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes
}

// sortEdgesStable sorts an edge slice in place by a precomputed stable key,
// computing each edge's key exactly once (decorate-sort) so very large graphs
// are not penalised by repeated JSON marshaling inside the comparison.
func sortEdgesStable(edges []*graph.Edge) {
	keys := make(map[*graph.Edge]string, len(edges))
	for _, e := range edges {
		keys[e] = edgeSortKey(e)
	}
	sort.SliceStable(edges, func(i, j int) bool { return keys[edges[i]] < keys[edges[j]] })
}

type bloodhoundMetadata struct {
	SourceKind string `json:"source_kind"`
}

type bloodhoundGraph struct {
	Edges []map[string]interface{} `json:"edges"`
	Nodes []map[string]interface{} `json:"nodes"`
}

type bloodhoundOutput struct {
	Metadata bloodhoundMetadata `json:"metadata"`
	Graph    bloodhoundGraph    `json:"graph"`
}

// buildEdgeDict serializes an edge to a BloodHound-compatible map, merging in EdgeInfo documentation
// (windowsAbuse, linuxAbuse, opsec, references, general) so BloodHound's entity panel can display them.
func buildEdgeDict(edge *graph.Edge) map[string]interface{} {
	edgeDict := map[string]interface{}{
		"kind": edge.Kind,
		"start": map[string]string{
			"value":    edge.Start.Value,
			"match_by": edge.Start.MatchBy,
		},
		"end": map[string]string{
			"value":    edge.End.Value,
			"match_by": edge.End.MatchBy,
		},
	}

	props := make(map[string]interface{})
	for k, v := range edge.Props {
		props[k] = v
	}

	if info, ok := graph.EdgeInfoMap[edge.Kind]; ok {
		if info.Description != "" {
			props["general"] = info.Description
		}
		if info.WindowsAbuse != "" {
			props["windowsAbuse"] = info.WindowsAbuse
		}
		if info.LinuxAbuse != "" {
			props["linuxAbuse"] = info.LinuxAbuse
		}
		if info.OpsecNotes != "" {
			props["opsec"] = info.OpsecNotes
		}
		if len(info.References) > 0 {
			props["references"] = strings.Join(info.References, "\n")
		}
	}

	if len(props) > 0 {
		edgeDict["properties"] = props
	}

	return edgeDict
}

// ExportToBloodHoundJSON exports the OpenGraph to BloodHound JSON format
func ExportToBloodHoundJSON(og *graph.OpenGraph, outputFile string, logger *logrus.Logger, debug bool, logLevel string) error {
	logger.Info("Starting export to BloodHound JSON format")

	// Adjust progress logging frequency based on log level
	var nodeInterval, edgeInterval int
	if logLevel == "WARNING" || logLevel == "ERROR" {
		nodeInterval = 10000
		edgeInterval = 50000
	} else if logLevel == "DEBUG" {
		nodeInterval = 25
		edgeInterval = 100
	} else { // INFO (default)
		nodeInterval = 100
		edgeInterval = 500
	}

	// Sort edges for deterministic, diff-friendly output.
	sortEdgesStable(og.InternalEdges)
	sortEdgesStable(og.ExternalEdges)

	// Convert nodes to JSON array (sorted by ID for deterministic output).
	nodesArray := make([]map[string]interface{}, 0, len(og.Nodes))
	totalNodes := len(og.Nodes)
	logger.Infof("Processing %d nodes...", totalNodes)

	idx := 0
	for _, node := range sortedNodes(og) {
		idx++
		if idx%nodeInterval == 0 || idx == totalNodes {
			logger.Infof("  Processed %d/%d nodes (%.1f%%)", idx, totalNodes, float64(idx)/float64(totalNodes)*100)
		}

		nodeDict := map[string]interface{}{
			"id":         node.ID,
			"kinds":      node.Kinds,
			"properties": node.Properties,
		}
		nodesArray = append(nodesArray, nodeDict)
	}

	// Convert internal edges to JSON array
	edgesArray := make([]map[string]interface{}, 0, len(og.InternalEdges))
	totalInternalEdges := len(og.InternalEdges)
	logger.Infof("Processing %d internal edges...", totalInternalEdges)

	for idx, edge := range og.InternalEdges {
		if (idx+1)%edgeInterval == 0 || idx+1 == totalInternalEdges {
			logger.Infof("  Processed %d/%d edges (%.1f%%)", idx+1, totalInternalEdges, float64(idx+1)/float64(totalInternalEdges)*100)
		}
		edgesArray = append(edgesArray, buildEdgeDict(edge))
	}

	// Convert external edges to JSON array
	externalEdgesArray := make([]map[string]interface{}, 0, len(og.ExternalEdges))
	totalExternalEdges := len(og.ExternalEdges)
	if totalExternalEdges > 0 {
		logger.Infof("Processing %d external edges...", totalExternalEdges)

		for idx, edge := range og.ExternalEdges {
			if (idx+1)%edgeInterval == 0 || idx+1 == totalExternalEdges {
				logger.Infof("  Processed %d/%d external edges (%.1f%%)", idx+1, totalExternalEdges, float64(idx+1)/float64(totalExternalEdges)*100)
			}
			externalEdgesArray = append(externalEdgesArray, buildEdgeDict(edge))
		}
	}

	// Merge internal and external edges
	allEdges := append(edgesArray, externalEdgesArray...)

	// Create the final structure
	output := bloodhoundOutput{
		Metadata: bloodhoundMetadata{
			SourceKind: "CyberArkBase",
		},
		Graph: bloodhoundGraph{
			Edges: allEdges,
			Nodes: nodesArray,
		},
	}

	// Write to file
	logger.Infof("Writing to file: %s", outputFile)
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warnf("Failed to close output file: %v", closeErr)
		}
	}()

	// Use buffered writer for better performance
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "") // Compact JSON for performance

	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	totalEdges := len(allEdges)
	logger.Infof("Export complete: nodes=%d internal_edges=%d external_edges=%d total=%d",
		totalNodes, totalInternalEdges, totalExternalEdges, totalEdges)

	return nil
}
