// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

import "strings"

// InfoSection is a single accordion section rendered in the BloodHound Entity
// Panel for a node or relationship kind. Introduced by BloodHound v9.5
// (2026-07-29), these schema-level "info" sections let an extension publish
// curated, markdown-formatted context once per kind — instead of duplicating it
// on every node/edge instance — which BloodHound serves from the entity lookup
// APIs when called with include-info=true.
//
// BloodHound renders the sections after the built-in "Object Information" panel,
// ordered by Position and then Title.
type InfoSection struct {
	Title    string       `json:"title"`
	Position int          `json:"position"`
	Markdown InfoMarkdown `json:"markdown"`
}

// InfoMarkdown holds the markdown body of an InfoSection.
type InfoMarkdown struct {
	Content string `json:"content"`
}

// Section identifiers used across node and relationship info blocks. Each id
// must match ^[a-z0-9_-]{1,128}$ per the OpenGraph schema.
const (
	infoOverview     = "overview"
	infoWindowsAbuse = "windows_abuse"
	infoLinuxAbuse   = "linux_abuse"
	infoAbuse        = "abuse"
	infoOpsec        = "opsec"
	infoReferences   = "references"
)

// fencedCode wraps a block of commands in a markdown fenced code block tagged
// with the given language so BloodHound renders it as monospaced code rather
// than collapsing the newlines into a single paragraph.
func fencedCode(lang, body string) string {
	body = strings.TrimRight(body, "\n")
	if body == "" {
		return ""
	}
	return "```" + lang + "\n" + body + "\n```"
}

// referencesMarkdown renders a list of reference URLs as a markdown bullet list.
func referencesMarkdown(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, ref := range refs {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("- <")
		b.WriteString(ref)
		b.WriteByte('>')
	}
	return b.String()
}

// EdgeInfoSections converts the curated EdgeInfo documentation for the given
// relationship kind into ordered Entity Panel accordion sections. Only sections
// with content are returned; a kind with no documentation returns nil so the
// schema omits an empty info block.
func EdgeInfoSections(kind string) map[string]InfoSection {
	info, ok := EdgeInfoMap[kind]
	if !ok {
		return nil
	}

	sections := map[string]InfoSection{}
	if info.Description != "" {
		sections[infoOverview] = InfoSection{
			Title:    "Overview",
			Position: 1,
			Markdown: InfoMarkdown{Content: info.Description},
		}
	}
	if body := fencedCode("powershell", info.WindowsAbuse); body != "" {
		sections[infoWindowsAbuse] = InfoSection{
			Title:    "Windows Abuse",
			Position: 2,
			Markdown: InfoMarkdown{Content: body},
		}
	}
	if body := fencedCode("bash", info.LinuxAbuse); body != "" {
		sections[infoLinuxAbuse] = InfoSection{
			Title:    "Linux Abuse",
			Position: 3,
			Markdown: InfoMarkdown{Content: body},
		}
	}
	if info.OpsecNotes != "" {
		sections[infoOpsec] = InfoSection{
			Title:    "OPSEC Considerations",
			Position: 4,
			Markdown: InfoMarkdown{Content: info.OpsecNotes},
		}
	}
	if body := referencesMarkdown(info.References); body != "" {
		sections[infoReferences] = InfoSection{
			Title:    "References",
			Position: 5,
			Markdown: InfoMarkdown{Content: body},
		}
	}

	if len(sections) == 0 {
		return nil
	}
	return sections
}

// NodeInfoSections converts the curated NodeInfo documentation for the given
// node kind into ordered Entity Panel accordion sections. Only sections with
// content are returned; a kind with no documentation returns nil.
func NodeInfoSections(kind string) map[string]InfoSection {
	info, ok := NodeInfoMap[kind]
	if !ok {
		return nil
	}

	sections := map[string]InfoSection{}
	if info.Overview != "" {
		sections[infoOverview] = InfoSection{
			Title:    "Overview",
			Position: 1,
			Markdown: InfoMarkdown{Content: info.Overview},
		}
	}
	if info.Abuse != "" {
		sections[infoAbuse] = InfoSection{
			Title:    "Abuse & Escalation",
			Position: 2,
			Markdown: InfoMarkdown{Content: info.Abuse},
		}
	}
	if info.OpsecNotes != "" {
		sections[infoOpsec] = InfoSection{
			Title:    "OPSEC Considerations",
			Position: 3,
			Markdown: InfoMarkdown{Content: info.OpsecNotes},
		}
	}
	if body := referencesMarkdown(info.References); body != "" {
		sections[infoReferences] = InfoSection{
			Title:    "References",
			Position: 4,
			Markdown: InfoMarkdown{Content: body},
		}
	}

	if len(sections) == 0 {
		return nil
	}
	return sections
}
