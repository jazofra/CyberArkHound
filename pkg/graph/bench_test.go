package graph_test

import (
	"io"
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/internal/synth"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/sirupsen/logrus"
)

// BenchmarkBuildOpenGraph builds a synthetic vault of 500 safes with 20
// accounts each (about 100k edges).
func BenchmarkBuildOpenGraph(b *testing.B) {
	in := synth.Vault(500, 20)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := graph.BuildOpenGraph(in, logger); err != nil {
			b.Fatal(err)
		}
	}
}
