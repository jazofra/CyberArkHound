package exporter

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/internal/synth"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/sirupsen/logrus"
)

// BenchmarkExport exports a synthetic vault of 500 safes with 20 accounts
// each (about 100k edges).
func BenchmarkExport(b *testing.B) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	og, err := graph.BuildOpenGraph(synth.Vault(500, 20), logger)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "export.json")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ExportToBloodHoundJSON(og, path, logger); err != nil {
			b.Fatal(err)
		}
	}
}
