// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

import (
	"fmt"
	"strconv"
	"strings"
)

// Link-based Entity Panel sections.
//
// BloodHound shows its native Members / Inbound Object Control tables only for
// the built-in Active Directory and Azure kinds. For OpenGraph kinds,
// BloodHound v9.7.0+ renders each info section's markdown as a Go template
// against the selected node. CyberArkHound uses that to give its nodes
// sections of Explore links, each running a Cypher query scoped to the
// selected node, which is the pattern SpecterOps' own Okta extension uses.
//
// Templates cannot query the graph, so these sections hold links, not counts
// or inline lists. On BloodHound older than v9.7.0 the template source is
// shown as plain text.

// ExploreQuery is one Explore link in a link-based section.
type ExploreQuery struct {
	// Label is the link text.
	Label string
	// Cypher is the query the link runs. Match the selected node with selfID;
	// its %[1]s is the only format verb a query may contain.
	Cypher string
}

// ExploreSection is an Entity Panel section made of Explore links.
type ExploreSection struct {
	// ID is the stable info section key (must match ^[a-z0-9_-]{1,128}$).
	ID string
	// Title is the accordion header.
	Title string
	// Intro is static markdown shown above the links.
	Intro string
	// Queries are rendered as a bullet list of Explore links.
	Queries []ExploreQuery
}

const (
	// selfID matches the selected node by objectid. The template fills %[1]s
	// with the node's objectid after stripping `"` and `\`, so a crafted object
	// name cannot end the string literal early.
	selfID = `{objectid: "%[1]s"}`

	// exploreURL is the Explore deep link; the query is base64 then URL encoded.
	exploreURL = "/ui/explore?exploreSearchTab=cypher&searchType=cypher&cypherSearch="

	// exploreOpen guards the links on the node having an objectid and binds
	// $id to it. The trailing -}} drops the newline so the list starts cleanly.
	exploreOpen = `{{ with .Properties.objectid }}{{ $id := printf "%v" . | replace "\\" "" | replace "\"" "" -}}` + "\n"

	// missingObjectIDNote replaces the links when the node has no objectid.
	missingObjectIDNote = "_This node has no `objectid`, so the Explore links can't be built._"

	exploreClose = "{{ else -}}\n" + missingObjectIDNote + "\n{{ end }}"
)

// Edge-kind unions used by the queries. Paths built from them only end where
// the union's edges can end, so a union can stand in for several fixed shapes.
const (
	// Traversable CyberArk edges from a principal to the credentials it can
	// obtain: membership, direct access, CCP, safe control, reconcile hijack.
	credentialPathKinds = "CyberArk_MemberOf|CyberArk_HasAccessTo|CyberArk_CanRetrieveViaCCP|CyberArk_CanGrantAccessTo|CyberArk_ManagedBy|CyberArk_Contains|CyberArk_CanHijackViaReconcile"

	// The escalation-only subset: no direct HasAccessTo or CCP retrieval.
	escalationPathKinds = "CyberArk_MemberOf|CyberArk_CanGrantAccessTo|CyberArk_ManagedBy|CyberArk_Contains|CyberArk_CanHijackViaReconcile"

	// AD group nesting plus the directory-sync bridges into the Vault.
	directoryPathKinds = "MemberOf|CyberArk_SyncsToUser|CyberArk_SyncsToGroup"

	// Edges from a stored credential to the AD objects it authenticates as.
	credentialBridgeKinds = "CyberArk_SyncsToADUser|CyberArk_CanConnect" //nolint:gosec // edge kinds, not a credential

	// First-degree AD control that lets an attacker take over an AD user.
	adUserControlKinds = "AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|Owns|OwnsLimitedRights|WriteDacl|WriteOwner|WriteOwnerLimitedRights|AddKeyCredentialLink|WriteSPN|WriteAltSecurityIdentities"

	// First-degree AD control that lets an attacker change an AD group's members.
	adGroupControlKinds = "AddMember|AddSelf|GenericAll|GenericWrite|Owns|OwnsLimitedRights|WriteDacl|WriteOwner|WriteOwnerLimitedRights"
)

// match builds "MATCH p=<pattern>\nRETURN p".
func match(pattern string) string {
	return "MATCH p=" + pattern + "\nRETURN p"
}

// self is the selected node's pattern for the given kind, e.g.
// (n:CyberArk_User {objectid: "%[1]s"}).
func self(kind string) string {
	return "(n:" + kind + " " + selfID + ")"
}

// reachableCredentials is the Reachable Credentials section for a Vault
// principal (user or group).
func reachableCredentials(kind, noun string, includeGroupInheritance bool) ExploreSection {
	n := self(kind)
	queries := []ExploreQuery{
		{"All reachable accounts", match(n + "-[:" + credentialPathKinds + "*1..]->(a:CyberArk_Account)")},
		{"Direct safe access", match(n + "-[:CyberArk_HasAccessTo]->(a:CyberArk_Account)")},
	}
	if includeGroupInheritance {
		queries = append(queries, ExploreQuery{"Inherited through group membership",
			match(n + "-[:CyberArk_MemberOf*1..]->(:CyberArk_Group)-[:CyberArk_HasAccessTo]->(a:CyberArk_Account)")})
	}
	queries = append(queries,
		ExploreQuery{"Through escalation (safe management, CPM, reconcile hijack)",
			match(n + "-[:" + escalationPathKinds + "*1..]->(a:CyberArk_Account)")},
		ExploreQuery{"AD users and computers these credentials unlock",
			match(n + "-[:" + credentialPathKinds + "*1..]->(:CyberArk_Account)-[:" + credentialBridgeKinds + "]->(t)")},
	)
	return ExploreSection{
		ID:    "reachable_credentials",
		Title: "Reachable Credentials",
		Intro: "Accounts whose credentials this " + noun + " can obtain, directly or by escalating. " +
			"The paths follow only traversable CyberArk edges.",
		Queries: queries,
	}
}

// NodeExploreSections lists the link-based Entity Panel sections for each node
// kind, in display order. NodeInfoSections places them after Overview.
var NodeExploreSections = map[string][]ExploreSection{
	"CyberArk_User": {
		{
			ID:    "member_of",
			Title: "Member Of",
			Intro: "Vault groups this user belongs to. Most safe permissions are granted to groups, so membership is usually where a user's access comes from.",
			Queries: []ExploreQuery{
				{"Vault groups", match(self("CyberArk_User") + "-[:CyberArk_MemberOf]->(g:CyberArk_Group)")},
				{"Vault groups granted through AD group sync", match(self("CyberArk_User") +
					"<-[:CyberArk_SyncsToUser]-(:User)-[:MemberOf*1..]->(:Group)-[:CyberArk_SyncsToGroup]->(g:CyberArk_Group)")},
			},
		},
		{
			ID:    "inbound_control",
			Title: "Inbound Control",
			Intro: "Who can take over this Vault user. A directory-synced user logs on with its AD credentials, so control of the synced AD user is control of this user. " +
				"Local (non-LDAP) users have no inbound edges, so these links return nothing for them.",
			Queries: []ExploreQuery{
				{"Synced AD user", match("(ad:User)-[:CyberArk_SyncsToUser]->" + self("CyberArk_User"))},
				{"AD principals with control of the synced AD user", match("(x)-[:" + adUserControlKinds +
					"]->(:User)-[:CyberArk_SyncsToUser]->" + self("CyberArk_User"))},
				{"Group-inherited control of the synced AD user", match("(m)-[:MemberOf*1..]->(:Group)-[:" + adUserControlKinds +
					"]->(:User)-[:CyberArk_SyncsToUser]->" + self("CyberArk_User"))},
			},
		},
		reachableCredentials("CyberArk_User", "user", true),
	},

	"CyberArk_Group": {
		{
			ID:    "members",
			Title: "Members",
			Intro: "Who belongs to this Vault group and inherits every permission granted to it. For a directory-mapped group, membership comes from the mapped AD group.",
			Queries: []ExploreQuery{
				{"Vault members", match("(m)-[:CyberArk_MemberOf]->" + self("CyberArk_Group"))},
				{"Mapped AD group", match("(ad:Group)-[:CyberArk_SyncsToGroup]->" + self("CyberArk_Group"))},
				{"AD members through directory sync", match("(m)-[:MemberOf*1..]->(:Group)-[:CyberArk_SyncsToGroup]->" + self("CyberArk_Group"))},
			},
		},
		{
			ID:    "inbound_control",
			Title: "Inbound Control",
			Intro: "Who can add members to this group. For a directory-mapped group, anyone who can change the membership of the mapped AD group, or of a group nested in it, gets this group's access after the next LDAP sync. " +
				"Adding members to a Vault-local group takes Vault user-management rights, which CyberArkHound does not model.",
			Queries: []ExploreQuery{
				{"AD principals that can change the mapped AD group's membership", match("(x)-[:" + adGroupControlKinds +
					"]->(:Group)-[:MemberOf|CyberArk_SyncsToGroup*1..]->" + self("CyberArk_Group"))},
				{"Group-inherited control of the mapped AD group", match("(m)-[:MemberOf*1..]->(:Group)-[:" + adGroupControlKinds +
					"]->(:Group)-[:CyberArk_SyncsToGroup]->" + self("CyberArk_Group"))},
			},
		},
		reachableCredentials("CyberArk_Group", "group", false),
	},

	"CyberArk_Safe": {
		{
			ID:    "members",
			Title: "Safe Members",
			Intro: "Safe members, grouped by what their permissions let them do. CyberArkHound stores safe membership as permission edges, so each link shows one kind of access.",
			Queries: []ExploreQuery{
				{"Can use or retrieve accounts", match("(m)-[:CyberArk_HasAccessTo]->(:CyberArk_Account)<-[:CyberArk_Contains]-" + self("CyberArk_Safe"))},
				{"Can manage the safe or its members", match("(m)-[:CyberArk_CanGrantAccessTo]->" + self("CyberArk_Safe"))},
				{"Can approve access requests", match("(m)-[:CyberArk_CanApprove]->" + self("CyberArk_Safe"))},
				{"CCP applications", match("(app:CyberArk_Application)-[:CyberArk_CanRetrieveViaCCP]->(:CyberArk_Account)<-[:CyberArk_Contains]-" + self("CyberArk_Safe"))},
				{"Managing CPM and creator", match("(m:CyberArk_User)-[:CyberArk_ManagedBy|CyberArk_Created]->" + self("CyberArk_Safe"))},
			},
		},
		{
			ID:    "inbound_control",
			Title: "Inbound Control",
			Intro: "Principals that control this safe. Each one can grant itself retrieve access and read every account in it.",
			Queries: []ExploreQuery{
				{"Vault principals, including through groups", match("(x)-[:CyberArk_MemberOf|CyberArk_CanGrantAccessTo|CyberArk_ManagedBy*1..]->" + self("CyberArk_Safe"))},
				{"Including AD principals through directory sync", match("(x)-[:" + directoryPathKinds +
					"|CyberArk_MemberOf|CyberArk_CanGrantAccessTo|CyberArk_ManagedBy*1..]->" + self("CyberArk_Safe"))},
			},
		},
		{
			ID:    "reachable_credentials",
			Title: "Reachable Credentials",
			Intro: "The credentials in this safe: what any principal that controls it can obtain.",
			Queries: []ExploreQuery{
				{"Accounts in this safe", match(self("CyberArk_Safe") + "-[:CyberArk_Contains]->(a:CyberArk_Account)")},
				{"AD users and computers they unlock", match(self("CyberArk_Safe") + "-[:CyberArk_Contains]->(:CyberArk_Account)-[:" + credentialBridgeKinds + "]->(t)")},
			},
		},
	},

	"CyberArk_Account": {
		{
			ID:    "inbound_control",
			Title: "Inbound Control",
			Intro: "Who can obtain this credential, following only traversable CyberArk edges. The containing safe appears in escalation paths because controlling the safe is how those principals reach the account. " +
				"The last two links are context: linked accounts control this one against the edge direction, and audit history is not a current access right.",
			Queries: []ExploreQuery{
				{"All inbound credential paths", match("(x)-[:" + credentialPathKinds + "*1..]->" + self("CyberArk_Account"))},
				{"Including AD principals through directory sync", match("(x)-[:" + directoryPathKinds + "|" + credentialPathKinds + "*1..]->" + self("CyberArk_Account"))},
				{"Direct access (safe members and CCP applications)", match("(x)-[:CyberArk_HasAccessTo|CyberArk_CanRetrieveViaCCP]->" + self("CyberArk_Account"))},
				{"Inherited through group membership", match("(m)-[:CyberArk_MemberOf*1..]->(:CyberArk_Group)-[:CyberArk_HasAccessTo]->" + self("CyberArk_Account"))},
				{"Through safe control (CanGrantAccessTo, CPM)", match("(x)-[:CyberArk_CanGrantAccessTo|CyberArk_ManagedBy]->(:CyberArk_Safe)-[:CyberArk_Contains]->" + self("CyberArk_Account"))},
				{"Reconcile-hijack paths", match("(x)-[:CyberArk_CanHijackViaReconcile]->" + self("CyberArk_Account"))},
				{"Linked accounts CyberArk uses to manage it (logon, reconcile)", match(self("CyberArk_Account") + "-[:CyberArk_LinkedTo]->(l:CyberArk_Account)")},
				{"Users who have used it (audit history)", match("(u:CyberArk_User)-[:CyberArk_UsedAccount]->" + self("CyberArk_Account"))},
			},
		},
		{
			ID:    "credential_reach",
			Title: "Credential Reach",
			Intro: "What this credential unlocks once someone obtains it.",
			Queries: []ExploreQuery{
				{"AD users and computers", match(self("CyberArk_Account") + "-[:" + credentialBridgeKinds + "]->(t)")},
				{"Accounts that depend on it (logon and reconcile blast radius)", match("(d:CyberArk_Account)-[:CyberArk_LinkedTo]->" + self("CyberArk_Account"))},
			},
		},
	},

	"CyberArk_Application": {
		{
			ID:    "inbound_control",
			Title: "Inbound Control",
			Intro: "Where this AppID can be used from. CCP only accepts the AppID from its allowed machines, so code running on one of them can retrieve the AppID's credentials; when the edge's `machineIsOnlyRestriction` is true, nothing else is checked. " +
				"An AppID whose `isUnrestricted` property is true has no allowed-machine list and can be used from anywhere that reaches CCP.",
			Queries: []ExploreQuery{
				{"Allowed machines", match(self("CyberArk_Application") + "-[:CyberArk_CCPAllowedFrom]->(c)")},
				{"Local admins of allowed machines", match("(x)-[:AdminTo]->(c:Computer)<-[:CyberArk_CCPAllowedFrom]-" + self("CyberArk_Application"))},
			},
		},
		{
			ID:    "reachable_credentials",
			Title: "Reachable Credentials",
			Intro: "Accounts this AppID can retrieve from CCP.",
			Queries: []ExploreQuery{
				{"Retrievable accounts", match(self("CyberArk_Application") + "-[:CyberArk_CanRetrieveViaCCP]->(a:CyberArk_Account)")},
				{"AD users and computers they unlock", match(self("CyberArk_Application") + "-[:CyberArk_CanRetrieveViaCCP]->(:CyberArk_Account)-[:" + credentialBridgeKinds + "]->(t)")},
			},
		},
	},
}

// Markdown renders the section as a BloodHound Entity Panel Go template: the
// intro, then one Explore link per query, guarded on the selected node having
// an objectid.
func (s ExploreSection) Markdown() string {
	var b strings.Builder
	b.WriteString(s.Intro)
	b.WriteString("\n\n")
	b.WriteString(exploreOpen)
	for _, q := range s.Queries {
		fmt.Fprintf(&b, "- [%s](%s{{ printf %s $id | b64enc | urlquery }})\n",
			q.Label, exploreURL, strconv.Quote(q.Cypher))
	}
	b.WriteString(exploreClose)
	return b.String()
}
