package exporter

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/internal/synth"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/sirupsen/logrus"
)

func TestZZBaseline(t *testing.T) {
	out := os.Getenv("BASELINE_OUT")
	if out == "" {
		t.Skip()
	}
	l := logrus.New()
	l.SetOutput(io.Discard)
	in := synth.Vault(300, 20)
	in.Now = time.Unix(1700000000, 0)
	og, err := graph.BuildOpenGraph(in, l)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExportToBloodHoundJSON(og, out, l); err != nil {
		t.Fatal(err)
	}
}
