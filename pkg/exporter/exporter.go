// Package exporter provides functions to export CyberArk OpenGraph data
// to BloodHound-compatible JSON format with progress logging.
package exporter

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/siemens-healthineers/cyberarkhound/internal/atomicfile"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/sirupsen/logrus"
)

// edgeLess orders edges by kind, start, end and finally properties, so that
// exports are deterministic across runs (two collections of the same
// environment diff cleanly). Properties are only serialized when two edges
// share kind, start and end, which is rare, so sorting very large graphs does
// not marshal every edge or hold a sort key per edge in memory.
func edgeLess(a, b *graph.Edge) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Start.Value != b.Start.Value {
		return a.Start.Value < b.Start.Value
	}
	if a.End.Value != b.End.Value {
		return a.End.Value < b.End.Value
	}
	pa, _ := json.Marshal(a.Props)
	pb, _ := json.Marshal(b.Props)
	return string(pa) < string(pb)
}

// sortEdgesStable sorts an edge slice in place into deterministic order.
func sortEdgesStable(edges []*graph.Edge) {
	sort.SliceStable(edges, func(i, j int) bool { return edgeLess(edges[i], edges[j]) })
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

// edgeJSON and nodeJSON are the exported forms of an edge and a node.
// Marshaling a struct avoids building a map per element; the fields are in
// alphabetical order, the order encoding/json uses for map keys, so the bytes
// are the same as those of the map form used before.
//
// Edge documentation (overview, windows/linux abuse, OPSEC, references) is not
// copied onto every edge instance. As of BloodHound v9.5 (2026-07-29) that
// curated context lives once per relationship kind in the OpenGraph schema
// (extension/schema.json "info" sections) and BloodHound serves it from the
// entity lookup APIs with include-info=true. Only the edge's own data
// properties are emitted.
type edgeJSON struct {
	End        edgeRefJSON            `json:"end"`
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Start      edgeRefJSON            `json:"start"`
}

type edgeRefJSON struct {
	MatchBy string `json:"match_by"`
	Value   string `json:"value"`
}

type nodeJSON struct {
	ID         string                 `json:"id"`
	Kinds      []string               `json:"kinds"`
	Properties map[string]interface{} `json:"properties"`
}

func toEdgeJSON(edge *graph.Edge) edgeJSON {
	return edgeJSON{
		End:        edgeRefJSON{MatchBy: edge.End.MatchBy, Value: edge.End.Value},
		Kind:       edge.Kind,
		Properties: edge.Props,
		Start:      edgeRefJSON{MatchBy: edge.Start.MatchBy, Value: edge.Start.Value},
	}
}

// IsZipPath reports whether outputFile asks for a zip archive (by its .zip
// extension) rather than plain JSON.
func IsZipPath(outputFile string) bool {
	return strings.EqualFold(filepath.Ext(outputFile), ".zip")
}

// ExportToBloodHoundJSON exports the OpenGraph to BloodHound JSON format.
//
// When outputFile ends in ".zip" the JSON is written as the single entry of a
// zip archive, which BloodHound accepts for upload and which is far smaller
// for large environments. The file is written atomically with mode 0600: it
// only appears once complete, and a failed export leaves any previous file at
// that path untouched.
func ExportToBloodHoundJSON(og *graph.OpenGraph, outputFile string, logger *logrus.Logger) error {
	logger.Info("Starting export to BloodHound JSON format")

	// Sort edges for deterministic, diff-friendly output.
	sortEdgesStable(og.InternalEdges)
	sortEdgesStable(og.ExternalEdges)

	logger.Infof("Writing to file: %s", outputFile)
	err := atomicfile.Write(outputFile, func(f io.Writer) error {
		if !IsZipPath(outputFile) {
			return writeGraphJSON(f, og, logger)
		}
		zw := zip.NewWriter(f)
		entryName := strings.TrimSuffix(filepath.Base(outputFile), filepath.Ext(outputFile)) + ".json"
		entry, err := zw.Create(entryName)
		if err != nil {
			return err
		}
		if err := writeGraphJSON(entry, og, logger); err != nil {
			return err
		}
		return zw.Close()
	})
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", outputFile, err)
	}

	logger.Infof("Export complete: nodes=%d internal_edges=%d external_edges=%d total=%d",
		len(og.Nodes), len(og.InternalEdges), len(og.ExternalEdges), len(og.InternalEdges)+len(og.ExternalEdges))
	return nil
}

// writeGraphJSON streams the graph to out as BloodHound OpenGraph JSON.
//
// The graph can contain millions of nodes and edges. Materializing every
// element as a map[string]interface{}, concatenating them into one slice and
// handing the whole structure to json.Encoder.Encode forces the entire
// serialized document (plus intermediate marshaling buffers) to live in memory
// at once, which exhausts RAM on large environments. Instead the JSON is
// streamed element by element: each node/edge is marshaled, written and then
// discarded, so peak memory stays flat regardless of graph size.
func writeGraphJSON(out io.Writer, og *graph.OpenGraph, logger *logrus.Logger) error {
	// Adjust progress logging frequency based on log level
	var nodeInterval, edgeInterval int
	switch {
	case logger.IsLevelEnabled(logrus.DebugLevel):
		nodeInterval = 25
		edgeInterval = 100
	case logger.IsLevelEnabled(logrus.InfoLevel):
		nodeInterval = 100
		edgeInterval = 500
	default:
		nodeInterval = 10000
		edgeInterval = 50000
	}

	totalNodes := len(og.Nodes)
	totalInternalEdges := len(og.InternalEdges)
	totalExternalEdges := len(og.ExternalEdges)

	// Buffer writes so each small Marshal result doesn't translate into a
	// syscall; 1 MiB keeps throughput high without notable memory cost.
	w := bufio.NewWriterSize(out, 1<<20)

	if _, err := io.WriteString(w, `{"metadata":{"source_kind":"CyberArkBase"},"graph":{"edges":[`); err != nil {
		return err
	}

	// writeElement marshals a single value and appends it to the current JSON
	// array, inserting a separating comma before every element after the first.
	writeElement := func(written *bool, v interface{}) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if *written {
			if err := w.WriteByte(','); err != nil {
				return err
			}
		}
		*written = true
		_, err = w.Write(b)
		return err
	}

	// Stream internal then external edges into the same array.
	edgeWritten := false
	logger.Infof("Processing %d internal edges...", totalInternalEdges)
	for idx, edge := range og.InternalEdges {
		if (idx+1)%edgeInterval == 0 || idx+1 == totalInternalEdges {
			logger.Infof("  Processed %d/%d edges (%.1f%%)", idx+1, totalInternalEdges, float64(idx+1)/float64(totalInternalEdges)*100)
		}
		if err := writeElement(&edgeWritten, toEdgeJSON(edge)); err != nil {
			return err
		}
	}
	if totalExternalEdges > 0 {
		logger.Infof("Processing %d external edges...", totalExternalEdges)
		for idx, edge := range og.ExternalEdges {
			if (idx+1)%edgeInterval == 0 || idx+1 == totalExternalEdges {
				logger.Infof("  Processed %d/%d external edges (%.1f%%)", idx+1, totalExternalEdges, float64(idx+1)/float64(totalExternalEdges)*100)
			}
			if err := writeElement(&edgeWritten, toEdgeJSON(edge)); err != nil {
				return err
			}
		}
	}

	// Close the edges array and open the nodes array.
	if _, err := io.WriteString(w, `],"nodes":[`); err != nil {
		return err
	}

	// Stream nodes (sorted by ID for deterministic output).
	logger.Infof("Processing %d nodes...", totalNodes)
	nodeWritten := false
	for idx, node := range sortedNodes(og) {
		if (idx+1)%nodeInterval == 0 || idx+1 == totalNodes {
			logger.Infof("  Processed %d/%d nodes (%.1f%%)", idx+1, totalNodes, float64(idx+1)/float64(totalNodes)*100)
		}
		if err := writeElement(&nodeWritten, nodeJSON{ID: node.ID, Kinds: node.Kinds, Properties: node.Properties}); err != nil {
			return err
		}
	}

	// Close the nodes array, graph object and root object.
	if _, err := io.WriteString(w, "]}}\n"); err != nil {
		return err
	}
	return w.Flush()
}
