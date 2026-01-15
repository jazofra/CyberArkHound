package graph

import (
	"net/url"
	"strings"
	"unicode"
)

// PVWATagFromArg derives a deterministic, human-recognizable 4-character tag from the --pvwa argument.
//
// Algorithm (hostname-based acronym):
// - 2 characters from the leftmost DNS label
// - 2 characters from the next label tokens (split on '-' and '_')
//
// Examples:
// - aps.varian.com -> APVA
// - cyberark.siemens-healthineers.com -> CYSH
func PVWATagFromArg(pvwaArg string) string {
	host := extractHostname(pvwaArg)
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "PVWA"
	}

	labels := strings.Split(host, ".")
	leftLabel := labels[0]
	nextLabel := ""
	if len(labels) > 1 {
		nextLabel = labels[1]
	}

	leftClean := keepAlphaNum(leftLabel)
	if leftClean == "" {
		return "PVWA"
	}

	prefix := leftClean
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}

	suffix := ""
	if nextLabel != "" {
		tokens := splitTokens(nextLabel)
		if len(tokens) >= 2 {
			suffix = keepAlphaNum(tokens[0])
			if suffix != "" {
				suffix = suffix[:1]
			}
			second := keepAlphaNum(tokens[1])
			if second != "" {
				suffix += second[:1]
			}
		} else if len(tokens) == 1 {
			suffix = keepAlphaNum(tokens[0])
			if len(suffix) > 2 {
				suffix = suffix[:2]
			}
		}
	}

	tag := prefix + suffix

	// Pad deterministically if we couldn't form 4 characters.
	if len(tag) < 4 {
		remainingLeft := ""
		if len(leftClean) > len(prefix) {
			remainingLeft = leftClean[len(prefix):]
		}
		filler := remainingLeft + keepAlphaNum(nextLabel)
		for len(tag) < 4 && filler != "" {
			tag += filler[:1]
			filler = filler[1:]
		}
	}
	for len(tag) < 4 {
		tag += "X"
	}
	if len(tag) > 4 {
		tag = tag[:4]
	}

	return strings.ToUpper(tag)
}

func extractHostname(pvwaArg string) string {
	s := strings.TrimSpace(pvwaArg)
	if s == "" {
		return ""
	}

	// Ensure url.Parse treats the input as a URL (otherwise host may be empty).
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err == nil {
		if host := strings.TrimSpace(u.Hostname()); host != "" {
			return host
		}
	}

	// Best-effort fallback: strip path and port.
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.SplitN(s, "/", 2)[0]
	if idx := strings.IndexByte(s, ':'); idx > 0 {
		s = s[:idx]
	}
	return s
}

func splitTokens(label string) []string {
	parts := strings.FieldsFunc(label, func(r rune) bool { return r == '-' || r == '_' })
	tokens := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		tokens = append(tokens, p)
	}
	return tokens
}

func keepAlphaNum(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
