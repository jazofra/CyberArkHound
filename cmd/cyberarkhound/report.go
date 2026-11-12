package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/internal/atomicfile"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/siemens-healthineers/cyberarkhound/pkg/snapshot"
)

// Findings report formats.
const (
	formatAuto     = "auto"
	formatJSON     = "json"
	formatSARIF    = "sarif"
	formatCSV      = "csv"
	formatMarkdown = "markdown"
)

// projectURL is where the tool and its findings documentation live.
const projectURL = "https://github.com/jazofra/CyberArkHound"

// markdownObjectLimit caps the objects listed per finding in a Markdown
// report, which is meant to be read; the JSON, CSV and SARIF reports list all.
const markdownObjectLimit = 100

// severities lists the finding severities from least to most severe.
var severities = []string{"low", "medium", "high", "critical"}

// severityLevel returns the position of a severity in severities, or -1.
func severityLevel(severity string) int {
	for i, s := range severities {
		if strings.EqualFold(s, severity) {
			return i
		}
	}
	return -1
}

// findingsAtOrAbove returns the findings whose severity is at least threshold.
func findingsAtOrAbove(findings []graph.Finding, threshold string) []graph.Finding {
	min := severityLevel(threshold)
	var out []graph.Finding
	for _, f := range findings {
		if severityLevel(f.Severity) >= min {
			out = append(out, f)
		}
	}
	return out
}

// normalizeFindingsFormat validates a --findings-format value.
func normalizeFindingsFormat(format string) (string, bool) {
	switch f := strings.ToLower(strings.TrimSpace(format)); f {
	case "", formatAuto:
		return formatAuto, true
	case formatJSON, formatSARIF, formatCSV, formatMarkdown:
		return f, true
	case "md":
		return formatMarkdown, true
	}
	return "", false
}

// findingsFormat resolves the report format: the explicit one, or the one
// the file name asks for, or JSON.
func findingsFormat(format, path string) string {
	if format != formatAuto && format != "" {
		return format
	}
	name := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(name, ".sarif"), strings.HasSuffix(name, ".sarif.json"):
		return formatSARIF
	case strings.HasSuffix(name, ".csv"):
		return formatCSV
	case strings.HasSuffix(name, ".md"), strings.HasSuffix(name, ".markdown"):
		return formatMarkdown
	}
	return formatJSON
}

// findingsReport is the document written by --findings-output.
type findingsReport struct {
	GeneratedAt time.Time       `json:"generatedAt"`
	CollectedAt time.Time       `json:"collectedAt"`
	PVWAURL     string          `json:"pvwaUrl"`
	PVWATag     string          `json:"pvwaTag"`
	Incomplete  []string        `json:"incomplete,omitempty"`
	Findings    []graph.Finding `json:"findings"`
}

func writeFindings(path, format string, snap *snapshot.Snapshot, findings []graph.Finding) error {
	if findings == nil {
		findings = []graph.Finding{}
	}
	report := findingsReport{
		GeneratedAt: time.Now().UTC(),
		CollectedAt: snap.CollectedAt,
		PVWAURL:     snap.PVWAURL,
		PVWATag:     snap.PVWATag,
		Incomplete:  snap.Incomplete,
		Findings:    findings,
	}
	write := writeFindingsJSON
	switch findingsFormat(format, path) {
	case formatSARIF:
		write = writeFindingsSARIF
	case formatCSV:
		write = writeFindingsCSV
	case formatMarkdown:
		write = writeFindingsMarkdown
	}
	return atomicfile.Write(path, func(w io.Writer) error { return write(w, report) })
}

func encodeIndented(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeFindingsJSON(w io.Writer, report findingsReport) error {
	return encodeIndented(w, report)
}

// describeObject names the object behind a finding: "name (ID)", and for a
// relationship "name (ID) -> name (ID)".
func describeObject(o graph.FindingObject) string {
	label := func(name, id string) string {
		if name == "" || name == id {
			return id
		}
		return fmt.Sprintf("%s (%s)", name, id)
	}
	s := label(o.Name, o.ID)
	if o.Target != "" {
		s += " -> " + label(o.TargetName, o.Target)
	}
	return s
}

// writeFindingsCSV writes one row per object behind a finding.
func writeFindingsCSV(w io.Writer, report findingsReport) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"finding_id", "severity", "title", "object_id", "object_name", "target_id", "target_name"})
	for _, f := range report.Findings {
		for _, o := range f.Objects {
			_ = cw.Write([]string{f.ID, f.Severity, f.Title, o.ID, csvText(o.Name), o.Target, csvText(o.TargetName)})
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvText keeps a name taken from the vault from being run as a formula by a
// spreadsheet that opens the report.
func csvText(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeFindingsMarkdown(w io.Writer, report findingsReport) error {
	var b strings.Builder
	// Names come from the vault; keep them from being read as Markdown.
	esc := strings.NewReplacer("\\", "\\\\", "|", "\\|", "`", "\\`", "*", "\\*", "_", "\\_", "<", "&lt;", "[", "\\[", "\n", " ").Replace

	b.WriteString("# CyberArkHound security findings\n\n")
	fmt.Fprintf(&b, "- PVWA: %s (tag %s)\n", esc(report.PVWAURL), esc(report.PVWATag))
	fmt.Fprintf(&b, "- Collected: %s\n", report.CollectedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339))
	if len(report.Incomplete) > 0 {
		b.WriteString("\n> **The collection is incomplete**, so findings may be missing:\n")
		for _, reason := range report.Incomplete {
			fmt.Fprintf(&b, "> - %s\n", esc(reason))
		}
	}
	if len(report.Findings) == 0 {
		b.WriteString("\nNo findings were detected in the collected data.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("\n| Severity | Finding | Count |\n|---|---|---:|\n")
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "| %s | %s (`%s`) | %d |\n", f.Severity, esc(f.Title), f.ID, f.Count)
	}
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "\n## %s\n\n", esc(f.Title))
		fmt.Fprintf(&b, "`%s` · %s · %d\n\n%s\n\n", f.ID, f.Severity, f.Count, esc(f.Detail))
		for i, o := range f.Objects {
			if i == markdownObjectLimit {
				fmt.Fprintf(&b, "- … and %d more (the JSON and CSV reports list them all)\n", len(f.Objects)-i)
				break
			}
			fmt.Fprintf(&b, "- %s\n", esc(describeObject(o)))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// SARIF 2.1.0, the subset code-scanning tools read.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool              `json:"tool"`
	Results    []sarifResult          `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifText              `json:"shortDescription"`
	FullDescription      sarifText              `json:"fullDescription"`
	DefaultConfiguration map[string]string      `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// sarifSeverity maps a finding severity to a SARIF level and to the
// security-severity score code-scanning tools rank results by.
func sarifSeverity(severity string) (level, score string) {
	switch severityLevel(severity) {
	case 3:
		return "error", "9.5"
	case 2:
		return "error", "8.0"
	case 1:
		return "warning", "5.0"
	}
	return "note", "2.0"
}

// writeFindingsSARIF writes one rule per finding and one result per object
// behind it. The objects are vault objects, not files, so they are reported
// as logical locations.
func writeFindingsSARIF(w io.Writer, report findingsReport) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "CyberArkHound",
			Version:        toolVersion(),
			InformationURI: projectURL,
			Rules:          []sarifRule{},
		}},
		Results: []sarifResult{},
		Properties: map[string]interface{}{
			"pvwaUrl":     report.PVWAURL,
			"pvwaTag":     report.PVWATag,
			"collectedAt": report.CollectedAt.UTC().Format(time.RFC3339),
		},
	}
	if len(report.Incomplete) > 0 {
		run.Properties["incomplete"] = report.Incomplete
	}
	for _, f := range report.Findings {
		level, score := sarifSeverity(f.Severity)
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:                   f.ID,
			Name:                 f.ID,
			ShortDescription:     sarifText{Text: f.Title},
			FullDescription:      sarifText{Text: f.Detail},
			DefaultConfiguration: map[string]string{"level": level},
			Properties:           map[string]interface{}{"severity": f.Severity, "security-severity": score, "tags": []string{"security"}},
		})
		for _, o := range f.Objects {
			locations := []sarifLogicalLocation{{Name: o.Name, FullyQualifiedName: o.ID, Kind: "resource"}}
			if o.Target != "" {
				locations = append(locations, sarifLogicalLocation{Name: o.TargetName, FullyQualifiedName: o.Target, Kind: "resource"})
			}
			run.Results = append(run.Results, sarifResult{
				RuleID:    f.ID,
				Level:     level,
				Message:   sarifText{Text: f.Title + ": " + describeObject(o)},
				Locations: []sarifLocation{{LogicalLocations: locations}},
			})
		}
	}
	return encodeIndented(w, sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}
