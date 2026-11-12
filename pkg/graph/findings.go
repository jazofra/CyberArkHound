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
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity string          `json:"severity"` // Critical, High, Medium or Low
	Count    int             `json:"count"`
	Detail   string          `json:"detail"`
	Objects  []FindingObject `json:"objects"`
}

// FindingObject identifies one object behind a finding: a node, or — for
// findings derived from relationships — the relationship's start (ID) and end
// (Target) nodes. Names are the nodes' display names, when known.
type FindingObject struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Target     string `json:"target,omitempty"`
	TargetName string `json:"targetName,omitempty"`
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
	case "Low":
		return 3
	default:
		return 4
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
// Only findings with at least one object are returned, ordered by severity;
// each finding's objects are sorted for stable output.
func ComputeFindings(og *OpenGraph) []Finding {
	objects := make(map[string][]FindingObject)
	nodeName := func(id string) string {
		if n := og.Nodes[id]; n != nil {
			return stringProp(n.Properties, "name")
		}
		return ""
	}
	addNode := func(findingID string, n *Node) {
		objects[findingID] = append(objects[findingID], FindingObject{ID: n.ID, Name: stringProp(n.Properties, "name")})
	}
	addEdge := func(findingID string, e *Edge) {
		objects[findingID] = append(objects[findingID], FindingObject{
			ID: e.Start.Value, Name: nodeName(e.Start.Value),
			Target: e.End.Value, TargetName: nodeName(e.End.Value),
		})
	}

	// Index the relationships the findings below reason about.
	type pair struct{ principal, safe string }
	safeOfAccount := make(map[string]string) // account node ID -> safe node ID
	accountsInSafe := make(map[string]int)   // safe node ID -> number of accounts
	for _, e := range og.InternalEdges {
		if e.Kind == "CyberArk_Contains" {
			safeOfAccount[e.End.Value] = e.Start.Value
			accountsInSafe[e.Start.Value]++
		}
	}
	holdsPermissions := make(map[string]bool) // principals with access or grant rights
	accessTo := make(map[pair]bool)           // principal can use accounts of the safe
	bypasses := make(map[pair]bool)           // ... and skips the approval they require
	for _, e := range og.InternalEdges {
		switch e.Kind {
		case "CyberArk_HasAccessTo":
			holdsPermissions[e.Start.Value] = true
			p := pair{e.Start.Value, safeOfAccount[e.End.Value]}
			accessTo[p] = true
			if boolProp(e.Props, "bypassesApproval") {
				bypasses[p] = true
			}
		case "CyberArk_CanGrantAccessTo":
			holdsPermissions[e.Start.Value] = true
		}
	}
	addPair := func(findingID string, p pair) {
		objects[findingID] = append(objects[findingID], FindingObject{
			ID: p.principal, Name: nodeName(p.principal),
			Target: p.safe, TargetName: nodeName(p.safe),
		})
	}
	for p := range bypasses {
		addPair("DUAL_CONTROL_BYPASS", p)
	}

	// A user's enabled flag is only meaningful when this PVWA reported it:
	// the basic user list leaves it out, and it then reads as false for
	// everyone.
	enabledReported := false
	for _, n := range og.Nodes {
		if nodeHasKind(n, "CyberArk_User") && boolProp(n.Properties, "enabled") {
			enabledReported = true
			break
		}
	}

	for _, n := range og.Nodes {
		// A principal that holds permissions but is missing from the user
		// and group lists cannot be reviewed like the others.
		if boolProp(n.Properties, "placeholder") && holdsPermissions[n.ID] &&
			(nodeHasKind(n, "CyberArk_User") || nodeHasKind(n, "CyberArk_Group")) {
			addNode("UNLISTED_PRINCIPAL_WITH_ACCESS", n)
		}
		// Placeholders stand for objects that were referenced but never
		// collected, so their (absent) settings say nothing.
		if boolProp(n.Properties, "placeholder") {
			continue
		}
		switch {
		case nodeHasKind(n, "CyberArk_Application"):
			if boolProp(n.Properties, "isUnrestricted") {
				addNode("CCP_UNRESTRICTED_APP", n)
			}
			if boolProp(n.Properties, "isDefaultCCPApp") {
				addNode("CCP_DEFAULT_AIMWEBSERVICE", n)
			}
		case nodeHasKind(n, "CyberArk_Platform"):
			if boolProp(n.Properties, "allowedSafesIsWildcard") {
				addNode("PLATFORM_WILDCARD_ALLOWEDSAFES", n)
			}
		case nodeHasKind(n, "CyberArk_Safe"):
			if stringProp(n.Properties, "managingCPM") == "" {
				addNode("SAFE_NO_CPM", n)
			}
		case nodeHasKind(n, "CyberArk_User"):
			if holdsPermissions[n.ID] && (boolProp(n.Properties, "suspended") ||
				(enabledReported && !boolProp(n.Properties, "enabled"))) {
				addNode("INACTIVE_USER_WITH_ACCESS", n)
			}
		case nodeHasKind(n, "CyberArk_Account"):
			if boolProp(n.Properties, "dualControlWithoutApprovers") {
				addNode("DUAL_CONTROL_NO_APPROVERS", n)
			}
			// Only judged when PVWA returned the account's secret-management
			// state; without it the flag is unknown, not off.
			if _, known := n.Properties["secretManagement"]; known && !boolProp(n.Properties, "automaticManagementEnabled") {
				addNode("ACCOUNT_NOT_MANAGED", n)
			}
			// PSM-breakout exposure: an account routed through a PSM server whose
			// platform has session isolation OR recording disabled — a quieter /
			// easier target for escaping the brokered session. Only count when the
			// platform data was present (the bool property exists and is false).
			if boolProp(n.Properties, "managedByPSM") {
				mon, monOK := n.Properties["sessionMonitoringEnabled"].(bool)
				rec, recOK := n.Properties["sessionRecordingEnabled"].(bool)
				if (monOK && !mon) || (recOK && !rec) {
					addNode("PSM_BREAKOUT_EXPOSURE", n)
				}
			}
		}
	}

	// Edge-derived findings.
	for _, e := range og.InternalEdges {
		switch e.Kind {
		case "CyberArk_CanRetrieveViaCCP":
			if boolProp(e.Props, "canRetrievePassword") && boolProp(e.Props, "appIsUnrestricted") {
				addEdge("CCP_UNRESTRICTED_RETRIEVAL", e)
			}
		case "CyberArk_CanHijackViaReconcile":
			addEdge("RECONCILE_HIJACK_EXPOSURE", e)
		case "CyberArk_CanGrantAccessTo":
			// The principal cannot use the safe's accounts today, but can
			// give itself (or anyone) that access.
			if accountsInSafe[e.End.Value] > 0 && !accessTo[pair{e.Start.Value, e.End.Value}] {
				addEdge("GRANT_WITHOUT_ACCESS", e)
			}
		}
	}

	candidates := []Finding{
		{
			ID:       "CCP_UNRESTRICTED_APP",
			Title:    "Unrestricted CCP applications (AppIDs)",
			Severity: "Critical",
			Detail:   "Applications with no authentication restriction (no Allowed Machines, OS user, path, hash, or certificate). Knowing the AppID is enough to retrieve their credentials via the CCP/AIMWebService endpoint.",
		},
		{
			ID:       "CCP_UNRESTRICTED_RETRIEVAL",
			Title:    "Credentials retrievable by unrestricted AppIDs via CCP",
			Severity: "Critical",
			Detail:   "Application→Account paths where an unrestricted AppID can retrieve the plaintext password through CCP, bypassing interactive login and dual-control approval.",
		},
		{
			ID:       "CCP_DEFAULT_AIMWEBSERVICE",
			Title:    "Default AIMWebService application present",
			Severity: "High",
			Detail:   "The out-of-the-box AIMWebService AppID usually has access to all safes and is a prime target. Restrict or remove it if unused.",
		},
		{
			ID:       "PLATFORM_WILDCARD_ALLOWEDSAFES",
			Title:    "Platforms with wildcard AllowedSafes (.*)",
			Severity: "High",
			Detail:   "Platforms whose AllowedSafes matches any safe can have their reconcile/logon accounts attached to unexpected safes, broadening the blast radius of a platform compromise.",
		},
		{
			ID:       "RECONCILE_HIJACK_EXPOSURE",
			Title:    "Reconcile-account hijack paths",
			Severity: "High",
			Detail:   "Principal->reconcile-account paths where a principal with addAccounts/manageSafe can coerce the CPM into using a privileged reconcile account to reset a chosen target's password (CyberArk_CanHijackViaReconcile).",
		},
		{
			ID:       "PSM_BREAKOUT_EXPOSURE",
			Title:    "PSM-routed accounts without session isolation/recording",
			Severity: "Medium",
			Detail:   "Accounts brokered by a PSM server whose platform has session isolation or recording disabled — a quieter and easier target for breaking out of the published session to reach the PSM host and the credentials it brokers.",
		},
		{
			ID:       "GRANT_WITHOUT_ACCESS",
			Title:    "Principals who can grant themselves access they do not have",
			Severity: "Medium",
			Detail:   "Principal->safe pairs where the principal can manage the safe or its members (CyberArk_CanGrantAccessTo) but has no access to the accounts in it. The access is one self-service permission change away, and reviews of who can use the accounts miss it.",
		},
		{
			ID:       "DUAL_CONTROL_BYPASS",
			Title:    "Principals who bypass dual-control approval",
			Severity: "Medium",
			Detail:   "Principal->safe pairs where accounts require approval (dual control) but the principal holds accessWithoutConfirmation and can use them unapproved.",
		},
		{
			ID:       "DUAL_CONTROL_NO_APPROVERS",
			Title:    "Dual control required but the safe has no approvers",
			Severity: "Medium",
			Detail:   "Accounts whose platform requires dual-control approval while no member of their safe can confirm requests. Check whether access to them is blocked or the control is not applied in practice.",
		},
		{
			ID:       "INACTIVE_USER_WITH_ACCESS",
			Title:    "Disabled or suspended users that still hold access",
			Severity: "Medium",
			Detail:   "Users that are disabled or suspended but remain safe members with access or grant rights. The permissions come back the moment the user is re-enabled.",
		},
		{
			ID:       "ACCOUNT_NOT_MANAGED",
			Title:    "Accounts with automatic management disabled",
			Severity: "Medium",
			Detail:   "Accounts the CPM does not manage (automaticManagementEnabled=false): their passwords are not rotated, verified or reconciled automatically.",
		},
		{
			ID:       "SAFE_NO_CPM",
			Title:    "Safes without CPM management",
			Severity: "Medium",
			Detail:   "Safes with no managing CPM do not have automated password rotation; stored credentials may be stale or unrotated.",
		},
		{
			ID:       "UNLISTED_PRINCIPAL_WITH_ACCESS",
			Title:    "Safe members missing from the user and group lists",
			Severity: "Low",
			Detail:   "Users and groups that hold safe permissions but were not returned by the Users or Groups API (placeholder nodes), for example deleted directory principals or ones the collector may not see. Their memberships and status could not be reviewed.",
		},
	}

	findings := make([]Finding, 0, len(candidates))
	for _, f := range candidates {
		objs := objects[f.ID]
		if len(objs) == 0 {
			continue
		}
		sort.Slice(objs, func(i, j int) bool {
			if objs[i].ID != objs[j].ID {
				return objs[i].ID < objs[j].ID
			}
			return objs[i].Target < objs[j].Target
		})
		f.Objects = objs
		f.Count = len(objs)
		findings = append(findings, f)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	return findings
}
