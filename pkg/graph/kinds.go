// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

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
