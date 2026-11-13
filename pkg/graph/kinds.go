// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

//go:generate go run ../../cmd/gen-schema

// NodeKinds is the canonical set of CyberArk node kinds CyberArkHound emits.
// It is the single source of truth used by the drift-guard test to keep
// extension/schema.json and cyberark_model.json in sync. When you add a node
// kind in builder.go, add it here too.
var NodeKinds = []string{
	"CyberArk_Instance",
	"CyberArk_User",
	"CyberArk_Group",
	"CyberArk_Safe",
	"CyberArk_Account",
	"CyberArk_Platform",
	"CyberArk_PSMServer",
	"CyberArk_ConnectionComponent",
	"CyberArk_Application",
}

// EdgeKinds is the canonical set of CyberArk edge kinds CyberArkHound emits.
// It is the single source of truth used by the drift-guard test to keep
// extension/schema.json (relationship_kinds) and pkg/graph/edge_info.go
// (EdgeInfoMap) in sync. When you add an edge kind in builder.go, add it here too.
var EdgeKinds = []string{
	"CyberArk_HasAccessTo",
	"CyberArk_CanRetrieveViaCCP",
	"CyberArk_CCPAllowedFrom",
	"CyberArk_CanHijackViaReconcile",
	"CyberArk_CanGrantAccessTo",
	"CyberArk_CanApprove",
	"CyberArk_MemberOf",
	"CyberArk_InstanceContains",
	"CyberArk_Contains",
	"CyberArk_Created",
	"CyberArk_ManagedBy",
	"CyberArk_UsesPlatform",
	"CyberArk_UsedAccount",
	"CyberArk_LinkedTo",
	"CyberArk_UsesPSMServer",
	"CyberArk_ManagedByPSM",
	"CyberArk_HasConnectionComponent",
	"CyberArk_PSMServerHostedOn",
	"CyberArk_SyncsToUser",
	"CyberArk_SyncsToGroup",
	"CyberArk_SyncsToADUser",
	"CyberArk_CanConnect",
}

// EdgeTraversability is the single source of truth for each edge kind's
// is_traversable flag in extension/schema.json. cmd/gen-schema writes it into
// the schema, and every kind in EdgeKinds must have an explicit entry.
//
// BloodHound defines a traversable relationship as one where "the starting node
// can take control of the ending node to a degree that lets an attacker abuse
// the ending node's outgoing edges". Only traversable edges are used for
// pathfinding and Attack Path analysis. Since BloodHound v9.x the Explore graph
// draws traversable edges as solid lines and non-traversable edges as dashed
// lines. Non-traversable edges still exist in the graph and stay queryable with
// explicit Cypher; they just never form part of a computed attack path.
//
// Choose false whenever control of the source does NOT hand the attacker the
// target, including cases where the attack runs in the opposite direction to the
// edge. A wrong true value creates false attack paths in pathfinding.
var EdgeTraversability = map[string]bool{
	// Principal can retrieve the password or open a PSM session as the account.
	"CyberArk_HasAccessTo": true,
	// manageSafe/manageSafeMembers: the principal can add itself with
	// retrieveAccounts and then read every account in the safe (via Contains).
	"CyberArk_CanGrantAccessTo": true,
	// The AppID can pull the credential from CCP with a single request.
	"CyberArk_CanRetrieveViaCCP": true,
	// Points AppID -> allowed host. The AppID does not control the host; the
	// attack runs the other way (land on the host, then present the AppID).
	"CyberArk_CCPAllowedFrom": false,
	// The principal can steer the CPM into using the privileged reconcile
	// account on a target of its choosing, which wields that credential.
	"CyberArk_CanHijackViaReconcile": true,
	// Approval authority alone grants no credential access; it only matters in
	// combination with a HasAccessTo edge on the same safe.
	"CyberArk_CanApprove": false,
	// Members inherit all of the group's safe permissions.
	"CyberArk_MemberOf": true,
	// Structural scoping from the PVWA instance to its configuration objects.
	"CyberArk_InstanceContains": false,
	// Access to the safe is access to every account it holds. Required so
	// CanGrantAccessTo / ManagedBy paths continue to the accounts.
	"CyberArk_Contains": true,
	// Informational: the creator's current rights are expressed by its own
	// safe-membership edges, not by having created the safe.
	"CyberArk_Created": false,
	// The CPM user holds full programmatic access to every account in the safes
	// it manages, so compromising it reaches those accounts.
	"CyberArk_ManagedBy": true,
	// Configuration mapping only.
	"CyberArk_UsesPlatform": false,
	// Historical audit evidence, not a current access right.
	"CyberArk_UsedAccount": false,
	// Points dependent account -> its logon/reconcile/additional account. The
	// dependency runs the opposite way to control: holding the dependent
	// account's password does not reveal the account it depends on (the
	// reconcile account can reset the dependent, not the reverse). Marking it
	// traversable made pathfinding report false paths such as
	// "access to any account -> its Domain Admin reconcile account". Use the
	// Cypher in docs/queries.md to walk these chains in the attack direction.
	"CyberArk_LinkedTo": false,
	// PSM infrastructure mapping only.
	"CyberArk_UsesPSMServer": false,
	"CyberArk_ManagedByPSM":  false,
	// Session protocol configuration only.
	"CyberArk_HasConnectionComponent": false,
	// Points PSM server -> its host. Infrastructure correlation only.
	"CyberArk_PSMServerHostedOn": false,
	// Compromising the AD user yields the Vault user via LDAP logon.
	"CyberArk_SyncsToUser": true,
	// AD members of the mapped group become members of the Vault group.
	"CyberArk_SyncsToGroup": true,
	// Retrieving the stored credential yields the AD user.
	"CyberArk_SyncsToADUser": true,
	// The stored credential authenticates to the host, often as local admin.
	"CyberArk_CanConnect": true,
}
