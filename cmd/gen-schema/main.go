// Command gen-schema regenerates extension/schema.json, injecting the curated
// Entity Panel "info" sections from the Go source of truth (graph.NodeInfoMap
// and graph.EdgeInfoMap) into every node and relationship kind. All other
// fields in schema.json are preserved verbatim.
//
// Run it from the repository root:
//
//	go run ./cmd/gen-schema
//
// or via `go generate ./...` (see the directive in pkg/graph). The drift-guard
// test in pkg/graph fails if the committed schema.json is out of sync with the
// Go maps, so run this whenever NodeInfoMap or EdgeInfoMap changes.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-schema:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	path := filepath.Join(root, "extension", "schema.json")
	existing, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	out, err := graph.BuildSchemaJSON(existing)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	fmt.Printf("wrote %s (%d bytes)\n", path, len(out))
	return nil
}

// repoRoot walks up from the current working directory to find the module root
// (the directory containing go.mod). This lets the generator work both when run
// manually from the repository root and when invoked via `go generate`, which
// sets the working directory to the package holding the directive.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate go.mod above %q", dir)
		}
		dir = parent
	}
}
