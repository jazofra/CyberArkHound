package graph

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNewOpenGraph(t *testing.T) {
	logger := logrus.New()
	og := NewOpenGraph(logger)

	if og.Nodes == nil {
		t.Error("Nodes map should be initialized")
	}
	if og.InternalEdges == nil {
		t.Error("InternalEdges slice should be initialized")
	}
	if og.ExternalEdges == nil {
		t.Error("ExternalEdges slice should be initialized")
	}
	if og.EdgeSet == nil {
		t.Error("EdgeSet map should be initialized")
	}
}

func TestNewOpenGraphWithCapacity(t *testing.T) {
	logger := logrus.New()
	nodeCount := 100
	edgeCount := 200

	og := NewOpenGraphWithCapacity(logger, nodeCount, edgeCount)

	if og.Nodes == nil {
		t.Error("Nodes map should be initialized")
	}
	if og.InternalEdges == nil {
		t.Error("InternalEdges slice should be initialized")
	}
	// Check capacity, but we can't easily check it directly without reflection or assuming implementation details
	// that are not exposed. However, checking it runs without panic is a good start.

	// Indirectly check if it works by adding items
	for i := 0; i < nodeCount; i++ {
		// Mock node addition logic
		og.Nodes[string(rune(i))] = &Node{}
	}

	if len(og.Nodes) != nodeCount {
		t.Errorf("Expected %d nodes, got %d", nodeCount, len(og.Nodes))
	}

	// Verify negative capacity handling
	ogNegative := NewOpenGraphWithCapacity(logger, -1, -1)
	if ogNegative.Nodes == nil {
		t.Error("Nodes map should be initialized even with negative capacity")
	}
}
