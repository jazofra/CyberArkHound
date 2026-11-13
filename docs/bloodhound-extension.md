# BloodHound extension

Icons, the OpenGraph extension schema, Entity Panel content and edge traversability.

[← Back to the README](../README.md)

## BloodHound Custom Node Definitions
The file `cyberark_model.json` defines custom node types (icons & colors) for BloodHound via the API Explorer `custom-nodes` endpoint:

```json
{
	"custom_types": {
		"CyberArk_Account":             {"icon": {"type": "font-awesome", "name": "user-secret", "color": "#E7C8C8"}},
		"CyberArk_Group":               {"icon": {"type": "font-awesome", "name": "user-group",  "color": "#C8DCC0"}},
		"CyberArk_Safe":                {"icon": {"type": "font-awesome", "name": "vault",       "color": "#E8D8B3"}},
		"CyberArk_User":                {"icon": {"type": "font-awesome", "name": "user",        "color": "#BFD6E3"}},
		"CyberArk_Platform":            {"icon": {"type": "font-awesome", "name": "server",      "color": "#D4B8D9"}},
		"CyberArk_PSMServer":           {"icon": {"type": "font-awesome", "name": "desktop",     "color": "#A8D5BA"}},
		"CyberArk_ConnectionComponent": {"icon": {"type": "font-awesome", "name": "plug",        "color": "#B8C9E0"}},
		"CyberArk_Application":         {"icon": {"type": "font-awesome", "name": "robot",       "color": "#F2C879"}}
	}
}
```

### Applying Custom Types
Use the BloodHound API (adjust host & auth):
```pwsh
curl -X POST -H "Content-Type: application/json" -d @cyberark_model.json https://bloodhound.example.com/api/custom-nodes
```
Or place/merge into your existing customization workflow before ingesting the exported graph.

After loading, BloodHound will render CyberArk nodes with meaningful icons/colors matching the diagram above.

### Maintaining
- Extend with additional CyberArk-derived types by adding entries under `custom_types`.
- Keep color palette distinct for rapid visual triage (avoid near-duplicate hex codes).
- Version the file if distributing across teams (e.g., `cyberark_model.v1.json`).

## BloodHound Entity Panel Info (OpenGraph `info`)

BloodHound v9.5 (2026-07-29) lets an OpenGraph extension publish **curated Entity Panel content once per kind**, instead of copying it onto every node and edge. `extension/schema.json` carries an `info` block on each node and relationship kind: a map of accordion sections keyed by a stable id, each with a `title`, an integer `position`, and a `markdown.content` body:

```json
"CyberArk_HasAccessTo": {
  "name": "CyberArk_HasAccessTo",
  "description": "…",
  "is_traversable": true,
  "info": {
    "overview":      { "title": "Overview",             "position": 1, "markdown": { "content": "…" } },
    "windows_abuse": { "title": "Windows Abuse",        "position": 2, "markdown": { "content": "```powershell\n…\n```" } },
    "linux_abuse":   { "title": "Linux Abuse",          "position": 3, "markdown": { "content": "```bash\n…\n```" } },
    "opsec":         { "title": "OPSEC Considerations", "position": 4, "markdown": { "content": "…" } },
    "references":    { "title": "References",           "position": 5, "markdown": { "content": "- <https://…>" } }
  }
}
```

BloodHound renders these sections in the Entity Panel accordion **after** the built-in **Object Information** panel, ordered by `position` then `title`, and serves them from the entity lookup APIs when called with `include-info=true` (e.g. `GET /api/v2/relationships/{id}?include-info=true`). Every CyberArkHound node kind (Instance, User, Group, Safe, Account, Platform, PSM Server, Connection Component, Application) and every relationship kind carries an overview plus, where relevant, abuse, OPSEC, and reference sections. Users, groups, safes, accounts and applications also get [Explore-link sections](#members-inbound-control-and-reachable-credentials-explore-links) for members, inbound control and reachable credentials.

Because this context now lives once per kind in the schema, CyberArkHound **no longer duplicates edge documentation onto every edge instance** in the exported graph — exports are considerably smaller, and only each edge's own data properties are emitted.

To load the panels, upload `extension/schema.json` as the CyberArk extension definition (alongside applying `cyberark_model.json` icons/colors) before ingesting the exported graph. The schema needs **BloodHound v9.7.0 or later**, because the Explore-link sections are Go templates.

### Traversable vs non-traversable edges (solid vs dashed)

BloodHound reads each relationship kind's `is_traversable` flag from the uploaded extension schema. It uses traversable edges for pathfinding and Attack Path analysis and draws them as solid lines in Explore. It draws non-traversable edges as dashed lines and never puts them in a computed path. The flag is set per kind, not per edge, so it takes effect when you upload `extension/schema.json`. Until then BloodHound doesn't know the CyberArk kinds and draws every CyberArk edge dashed. If you're upgrading, re-upload the schema so the new flags apply.

CyberArkHound marks an edge traversable only when controlling its source gives the attacker its target, which is BloodHound's definition. The decisions, each with its reason, live in `graph.EdgeTraversability` (`pkg/graph/kinds.go`). Every edge's **Overview** panel ends with a line saying whether it's traversable, and the [Edge Types Summary](edges.md#edge-types-summary) lists all of them. A few decisions are worth calling out:

- **`CyberArk_LinkedTo` is non-traversable** (changed in schema v2.2.0). The edge points from a dependent account to its logon or reconcile account, but control runs the other way. When it was traversable, pathfinding reported false paths such as "access to any account leads to its Domain Admin reconcile account". The [linked-account queries](queries.md#linked-account--credential-chains-cyberark_linkedto) start from the linked account to follow the attack direction.
- **`CyberArk_CCPAllowedFrom` and `CyberArk_PSMServerHostedOn` are non-traversable.** They point from CyberArk to an AD computer, but the attack runs from the computer into CyberArk (for example, land on an allowed host, then present the AppID). As traversable edges they would claim that an AppID controls its host.
- **`CyberArk_CanApprove`, `CyberArk_UsedAccount` and `CyberArk_Created` are non-traversable.** Approval authority, past usage and having created a safe don't grant credential access on their own. Whatever access these principals still hold shows up as their own `CyberArk_HasAccessTo` / `CyberArk_CanGrantAccessTo` edges.
- **`CyberArk_Contains` and `CyberArk_ManagedBy` are traversable** so that safe-level control (`CyberArk_CanGrantAccessTo`, the CPM user) carries on to the accounts inside the safe.

### Members, Inbound Control and Reachable Credentials (Explore links)

> **Requires BloodHound v9.7.0 (2026-09-08) or later.** These sections are Go templates, which BloodHound only renders from v9.7.0. Older versions show the template source as plain text.

BloodHound's native **Members**, **Member Of**, and **Inbound/Outbound Object Control** tables (with counts and expandable lists) are hard-coded in its UI for the built-in Active Directory and Azure kinds, so OpenGraph kinds can't get them. (The `expandedPanelSections` URL parameter only records which accordion sections are open; it can't add any.) Instead, CyberArkHound gives its main node kinds link-based sections that sit right after **Overview**. Each link opens **Explore** and runs a Cypher query scoped to the selected node, the same pattern SpecterOps' Okta extension uses. Templates can't query the graph, so the sections hold links rather than counts or inline lists.

| Node kind | Sections | What the links show |
|-----------|----------|---------------------|
| `CyberArk_User` | Member Of, Inbound Control, Reachable Credentials | Vault groups (direct and through AD group sync); the synced AD user and AD principals with control of it (direct and group-inherited); every account the user can obtain, split into direct, group-inherited and escalation paths, plus the AD users and computers those credentials unlock |
| `CyberArk_Group` | Members, Inbound Control, Reachable Credentials | Vault members, the mapped AD group and its AD members; AD principals that can change the mapped group's membership; reachable accounts as for users |
| `CyberArk_Safe` | Safe Members, Inbound Control, Reachable Credentials | Members by what they can do (use/retrieve, manage, approve, CCP AppIDs, CPM and creator); principals that control the safe, optionally including AD principals through directory sync; the accounts it holds and what they unlock in AD |
| `CyberArk_Account` | Inbound Control, Credential Reach | Every inbound credential path, split into direct, group-inherited, safe-control and reconcile-hijack paths, plus the linked accounts that manage it and its audit history; the AD users and computers it unlocks and the accounts that depend on it |
| `CyberArk_Application` | Inbound Control, Reachable Credentials | Allowed machines and their local admins; the accounts the AppID can retrieve from CCP and what they unlock in AD |

How the links work:

- Each link is `/ui/explore?exploreSearchTab=cypher&searchType=cypher&cypherSearch=<base64 query>`, built by the template from the selected node's `objectid`. Before the `objectid` goes into the query, `"` and `\` are stripped from it so an unusual object name can't end the Cypher string early. A node without an `objectid` shows a short note instead of links.
- Every query returns full paths (`MATCH p=… RETURN p`), like the [query library](queries.md#bloodhound-cypher-query-library). Credential paths follow only traversable CyberArk edges. The few non-traversable edges used (audit history, linked accounts, approvers, safe creator, allowed machines) are labeled as context.
- AD-side links use BloodHound's built-in AD kinds (`User`, `Group`, `Computer`, `MemberOf`, `AdminTo`, and first-degree control edges like `GenericAll`, `AddMember` and `ForceChangePassword`), so they return paths only when AD data is loaded. The "including AD principals" links follow AD group nesting and can be slow on large AD graphs.

### Maintaining the entity info

The panel content is generated from a single Go source of truth:

- Node content lives in `graph.NodeInfoMap` (`pkg/graph/node_info.go`).
- Edge content lives in `graph.EdgeInfoMap` (`pkg/graph/edge_info.go`).
- Link-based node sections (Members, Inbound Control, Reachable Credentials, …) live in `graph.NodeExploreSections` (`pkg/graph/explore_links.go`). Write each query with the selected node matched as `self("<Kind>")`. `pkg/graph/explore_links_test.go` parses every template with only BloodHound's allowed template functions, renders it, decodes every link back to its exact query, and checks each single-edge hop's direction against the edges `builder.go` emits.
- Edge traversability lives in `graph.EdgeTraversability` (`pkg/graph/kinds.go`) and is written to each relationship kind's `is_traversable`. `cmd/gen-schema` refuses to run if a relationship kind has no entry, so every new edge gets an explicit decision.
- `extension/schema.json` is generated from those maps by `cmd/gen-schema`.

After editing either map, regenerate the schema:

```bash
go generate ./...        # or: go run ./cmd/gen-schema
```

A drift-guard test (`pkg/graph/schema_test.go`) fails the build if `extension/schema.json` is out of sync with the Go maps, asserts every canonical kind ships a well-formed `info` block, and pins the traversability decisions that attack-path correctness depends on.
