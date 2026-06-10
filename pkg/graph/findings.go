// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

import "sort"

// Finding describes a security-relevant misconfiguration computed from the
// collected graph. Findings are derived entirely from data already present on
// nodes and edges (no extra API calls) and are surfaced at the end of a run so
// operators see the highest-value issues without writing Cypher.
//
// Several of these findings map the tradecraft presented by Marat Nigmatullin
// (FalconForce) in "4 GET requests = 3 Domain admins: CyberArk magic you didn't
// know about" (SO-CON 2026): unrestricted CCP AppIDs, the default AIMWebService
// application, and platforms with a wildcard AllowedSafes.
type Finding struct {
	ID       string
	Title    string
	Severity string // Critical, High, or Medium
	Count    int
	Detail   string
}

// severityRank orders findings from most to least severe for stable reporting.
func severityRank(sev string) int {
	switch sev {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	default:
		return 3
	}
}

// nodeHasKind reports whether a node carries the given kind label.
func nodeHasKind(n *Node, kind string) bool {
	for _, k := range n.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// boolProp returns the boolean value of a node/edge property, defaulting to false.
func boolProp(props map[string]interface{}, key string) bool {
	if v, ok := props[key].(bool); ok {
		return v
	}
	return false
}

// stringProp returns the string value of a property, defaulting to "".
func stringProp(props map[string]interface{}, key string) string {
	if v, ok := props[key].(string); ok {
		return v
	}
	return ""
}

// ComputeFindings derives the set of security findings from the built graph.
// Only findings with a non-zero count are returned, ordered by severity.
func ComputeFindings(og *OpenGraph) []Finding {
	var (
		unrestrictedApps  int
		defaultCCPApps    int
		wildcardPlatforms int
		safesNoCPM        int
	)

	for _, n := range og.Nodes {
		switch {
		case nodeHasKind(n, "CyberArk_Application"):
			if boolProp(n.Properties, "isUnrestricted") {
				unrestrictedApps++
			}
			if boolProp(n.Properties, "isDefaultCCPApp") {
				defaultCCPApps++
			}
		case nodeHasKind(n, "CyberArk_Platform"):
			if boolProp(n.Properties, "allowedSafesIsWildcard") {
				wildcardPlatforms++
			}
		case nodeHasKind(n, "CyberArk_Safe"):
			if stringProp(n.Properties, "managingCPM") == "" {
				safesNoCPM++
			}
		}
	}

	// Edge-derived findings.
	ccpUnrestrictedRetrieval := 0
	for _, e := range og.InternalEdges {
		if e.Kind == "CyberArk_CanRetrieveViaCCP" &&
			boolProp(e.Props, "canRetrievePassword") &&
			boolProp(e.Props, "appIsUnrestricted") {
			ccpUnrestrictedRetrieval++
		}
	}

	candidates := []Finding{
		{
			ID:       "CCP_UNRESTRICTED_APP",
			Title:    "Unrestricted CCP applications (AppIDs)",
			Severity: "Critical",
			Count:    unrestrictedApps,
			Detail:   "Applications with no authentication restriction (no Allowed Machines, OS user, path, hash, or certificate). Knowing the AppID is enough to retrieve their credentials via the CCP/AIMWebService endpoint.",
		},
		{
			ID:       "CCP_UNRESTRICTED_RETRIEVAL",
			Title:    "Credentials retrievable by unrestricted AppIDs via CCP",
			Severity: "Critical",
			Count:    ccpUnrestrictedRetrieval,
			Detail:   "Application→Account paths where an unrestricted AppID can retrieve the plaintext password through CCP, bypassing interactive login and dual-control approval.",
		},
		{
			ID:       "CCP_DEFAULT_AIMWEBSERVICE",
			Title:    "Default AIMWebService application present",
			Severity: "High",
			Count:    defaultCCPApps,
			Detail:   "The out-of-the-box AIMWebService AppID usually has access to all safes and is a prime target. Restrict or remove it if unused.",
		},
		{
			ID:       "PLATFORM_WILDCARD_ALLOWEDSAFES",
			Title:    "Platforms with wildcard AllowedSafes (.*)",
			Severity: "High",
			Count:    wildcardPlatforms,
			Detail:   "Platforms whose AllowedSafes matches any safe can have their reconcile/logon accounts attached to unexpected safes, broadening the blast radius of a platform compromise.",
		},
		{
			ID:       "SAFE_NO_CPM",
			Title:    "Safes without CPM management",
			Severity: "Medium",
			Count:    safesNoCPM,
			Detail:   "Safes with no managing CPM do not have automated password rotation; stored credentials may be stale or unrotated.",
		},
	}

	findings := make([]Finding, 0, len(candidates))
	for _, f := range candidates {
		if f.Count > 0 {
			findings = append(findings, f)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	return findings
}
