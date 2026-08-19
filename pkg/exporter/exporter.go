// Package exporter provides functions to export CyberArk OpenGraph data
// to BloodHound-compatible JSON format with progress logging.
package exporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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

// buildEdgeDict serializes an edge to a BloodHound-compatible map.
//
// Edge documentation (overview, windows/linux abuse, OPSEC, references) is no
// longer copied onto every edge instance. As of BloodHound v9.5 (2026-07-29)
// that curated context lives once per relationship kind in the OpenGraph schema
// (extension/schema.json "info" sections) and BloodHound serves it from the
// entity lookup APIs with include-info=true. Keeping it out of per-edge
// properties avoids repeating the same large text blocks across every edge and
// keeps exports lean. Only the edge's own data properties are emitted here.
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

	if len(edge.Props) > 0 {
		props := make(map[string]interface{}, len(edge.Props))
		for k, v := range edge.Props {
			props[k] = v
		}
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

	totalNodes := len(og.Nodes)
	totalInternalEdges := len(og.InternalEdges)
	totalExternalEdges := len(og.ExternalEdges)

	// Write to file.
	//
	// The graph can contain millions of nodes and edges. Materializing every
	// element as a map[string]interface{}, concatenating them into one slice
	// and handing the whole structure to json.Encoder.Encode forces the entire
	// serialized document (plus intermediate marshaling buffers) to live in
	// memory at once, which exhausts RAM on large environments. Instead we
	// stream the JSON element by element: each node/edge is marshaled,
	// written and then discarded, so peak memory stays flat regardless of
	// graph size.
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

	// Buffer writes so each small Marshal result doesn't translate into a
	// syscall; 1 MiB keeps throughput high without notable memory cost.
	w := bufio.NewWriterSize(file, 1<<20)

	if _, err := io.WriteString(w, `{"metadata":{"source_kind":"CyberArkBase"},"graph":{"edges":[`); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	// writeElement marshals a single value and appends it to the current JSON
	// array, inserting a separating comma before every element after the first.
	edgeWritten := false
	writeEdge := func(edge *graph.Edge) error {
		b, err := json.Marshal(buildEdgeDict(edge))
		if err != nil {
			return err
		}
		if edgeWritten {
			if err := w.WriteByte(','); err != nil {
				return err
			}
		}
		edgeWritten = true
		_, err = w.Write(b)
		return err
	}

	// Stream internal edges.
	logger.Infof("Processing %d internal edges...", totalInternalEdges)
	for idx, edge := range og.InternalEdges {
		if (idx+1)%edgeInterval == 0 || idx+1 == totalInternalEdges {
			logger.Infof("  Processed %d/%d edges (%.1f%%)", idx+1, totalInternalEdges, float64(idx+1)/float64(totalInternalEdges)*100)
		}
		if err := writeEdge(edge); err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}
	}

	// Stream external edges into the same array.
	if totalExternalEdges > 0 {
		logger.Infof("Processing %d external edges...", totalExternalEdges)
		for idx, edge := range og.ExternalEdges {
			if (idx+1)%edgeInterval == 0 || idx+1 == totalExternalEdges {
				logger.Infof("  Processed %d/%d external edges (%.1f%%)", idx+1, totalExternalEdges, float64(idx+1)/float64(totalExternalEdges)*100)
			}
			if err := writeEdge(edge); err != nil {
				return fmt.Errorf("failed to write JSON: %w", err)
			}
		}
	}

	// Close the edges array and open the nodes array.
	if _, err := io.WriteString(w, `],"nodes":[`); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	// Stream nodes (sorted by ID for deterministic output).
	logger.Infof("Processing %d nodes...", totalNodes)
	nodeWritten := false
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
		b, err := json.Marshal(nodeDict)
		if err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}
		if nodeWritten {
			if err := w.WriteByte(','); err != nil {
				return fmt.Errorf("failed to write JSON: %w", err)
			}
		}
		nodeWritten = true
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}
	}

	// Close the nodes array, graph object and root object.
	if _, err := io.WriteString(w, "]}}\n"); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush JSON: %w", err)
	}

	totalEdges := totalInternalEdges + totalExternalEdges
	logger.Infof("Export complete: nodes=%d internal_edges=%d external_edges=%d total=%d",
		totalNodes, totalInternalEdges, totalExternalEdges, totalEdges)

	return nil
}
