# Cypher query library

Ready-made BloodHound queries for every edge type and finding.

[← Back to the README](../README.md)

## BloodHound Cypher Query Library

A single catalogue of Cypher queries for the CyberArk OpenGraph, grouped by attack-path theme. Paste them into BloodHound's **Cypher search** (Explore → Cypher). Swap the example literals (`name: "jdoe"`, `"prod"`, …) for values from your environment.

**Every query returns the whole path.** Each query is written as `MATCH p=(…)-[…]->(…) RETURN p` so BloodHound draws the nodes *and* the edges between them (the actual attack path), never just a list of endpoint names or attributes. Even the "which platforms/safes/AppIDs are misconfigured" checks return a path — they walk the natural relationship (an account to its platform, a safe to its accounts, an application to the credentials it can reach) so the finding renders as a subgraph you can pivot from, not a flat table.

> **Tip — path *and* edge properties:** bind the relationship as well so you can sort or annotate by its properties while still returning the path, e.g. `MATCH p=(u)-[r:CyberArk_UsedAccount]->(a) RETURN p ORDER BY r.lastUsedTime DESC`. Edge/node properties stay visible on the rendered path.
>
> **Need a ranked count or a flat inventory instead?** Wrap any query below with an aggregation — e.g. `MATCH (pf:CyberArk_Platform)<-[:CyberArk_UsesPlatform]-(a) RETURN pf.name, count(a) ORDER BY count(a) DESC`. The library defaults to paths on purpose; reach for a tabular form only when you specifically want a count.

### Direct account access (`CyberArk_HasAccessTo`)
```cypher
// All accounts a specific user can access
MATCH p=(u:CyberArk_User {name: "jdoe"})-[:CyberArk_HasAccessTo]->(a:CyberArk_Account)
RETURN p

// All users who can access a specific account
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo]->(a:CyberArk_Account {name: "prod-db-admin"})
RETURN p

// LDAP-synced users with direct account access
MATCH p=(u:CyberArk_User {isLDAPSynced: true})-[:CyberArk_HasAccessTo]->(a:CyberArk_Account)
RETURN p

// Group-inherited access: user -> group(s) -> account (permission via membership)
MATCH p=(u:CyberArk_User)-[:CyberArk_MemberOf*1..]->(g:CyberArk_Group)-[:CyberArk_HasAccessTo]->(a:CyberArk_Account)
RETURN p
```

### Privilege escalation (`CyberArk_CanGrantAccessTo`)
```cypher
// Escalation paths: grant-access -> safe -> every account in it
MATCH p=(u:CyberArk_User)-[:CyberArk_CanGrantAccessTo]->(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
RETURN p

// Users who can grant themselves access to production safes
MATCH p=(u:CyberArk_User)-[:CyberArk_CanGrantAccessTo]->(s:CyberArk_Safe)
WHERE s.safeName CONTAINS "prod"
RETURN p

// Full escalation-to-AD path: escalate on a safe, reach a credential mapped to AD
MATCH p=(u:CyberArk_User)-[:CyberArk_CanGrantAccessTo]->(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(ad:User)
RETURN p
```

### Dual control (approval) analysis
```cypher
// Retrieve WITHOUT approval (highest risk) — one request and the password is yours
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo {requiresApproval: false}]->(a:CyberArk_Account)
RETURN p

// Retrieve only WITH approval — the attack needs an accessor AND an approver
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo {requiresApproval: true}]->(a:CyberArk_Account)
RETURN p

// Approvers and the dual-controlled accounts they gate
MATCH p=(approver)-[:CyberArk_CanApprove]->(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
RETURN p

// Full dual-control attack path: BOTH an accessor and an approver on the same account
MATCH access=(u:CyberArk_User)-[:CyberArk_HasAccessTo {requiresApproval: true}]->(a:CyberArk_Account)
MATCH approve=(a)<-[:CyberArk_Contains]-(s:CyberArk_Safe)<-[:CyberArk_CanApprove]-(approver)
RETURN access, approve

// Self-approval risk: the SAME principal is both accessor and approver
MATCH access=(u:CyberArk_User)-[:CyberArk_HasAccessTo {requiresApproval: true}]->(a:CyberArk_Account)
MATCH approve=(a)<-[:CyberArk_Contains]-(s:CyberArk_Safe)<-[:CyberArk_CanApprove]-(u)
RETURN access, approve

// Accounts on dual-control platforms sitting in safes with NO approver (policy gap)
MATCH p=(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {requireDualControlPasswordAccessApproval: true})
WHERE NOT ()-[:CyberArk_CanApprove]->(s)
RETURN p

// Accounts accessible with session monitoring OFF
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo {requiresSessionMonitoring: false}]->(a:CyberArk_Account)
RETURN p
```

Platform policy audits — each returns the accounts sitting on the flagged platform, so the exposure renders as a path:
```cypher
// Accounts on platforms with dual control ENABLED
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {requireDualControlPasswordAccessApproval: true})
RETURN p

// Accounts on platforms where dual control is DISABLED as a Master Policy exception (audit)
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform)
WHERE pf.requireDualControlPasswordAccessApproval = false AND pf.dualControlIsException = true
RETURN p

// Accounts on platforms where session monitoring is disabled as a Master Policy exception
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform)
WHERE pf.requirePrivilegedSessionMonitoringAndIsolation = false AND pf.sessionMonitoringIsException = true
RETURN p
```

### Actual usage / activity (`CyberArk_UsedAccount`)
```cypher
// Who actually used production accounts (path, sorted by recency via the bound edge)
MATCH p=(u:CyberArk_User)-[r:CyberArk_UsedAccount]->(a:CyberArk_Account)
WHERE a.safeName CONTAINS "prod"
RETURN p ORDER BY r.lastUsedTime DESC

// People only — leave out the CPM user's verify/change/reconcile housekeeping
MATCH p=(u:CyberArk_User)-[r:CyberArk_UsedAccount {credentialAccess: true}]->(a:CyberArk_Account)
RETURN p ORDER BY r.lastUsedTime DESC

// Granted but never used — dormant access worth pruning
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo]->(a:CyberArk_Account)
WHERE NOT (u)-[:CyberArk_UsedAccount {credentialAccess: true}]->(a)
RETURN p

// Used WITHOUT a matching access grant (possible escalation / audit gap)
MATCH p=(u:CyberArk_User)-[:CyberArk_UsedAccount]->(a:CyberArk_Account)
WHERE NOT (u)-[:CyberArk_HasAccessTo]->(a)
RETURN p

// Heaviest usage first — usage paths ordered by the edge's usageCount
MATCH p=(u:CyberArk_User)-[r:CyberArk_UsedAccount]->(a:CyberArk_Account)
RETURN p ORDER BY r.usageCount DESC
```

### Linked account / credential chains (`CyberArk_LinkedTo`)
```cypher
// Accounts that depend on a specific logon account
MATCH p=(logon:CyberArk_Account {name: "svc-logon"})<-[:CyberArk_LinkedTo {linkType: "logon"}]-(a:CyberArk_Account)
RETURN p

// Multi-hop dependency chains. Control runs against the arrows: compromising the
// account at the end of a chain reaches every account before it. (LinkedTo is
// non-traversable, so BloodHound pathfinding won't build these paths for you.)
MATCH p=(a:CyberArk_Account)-[:CyberArk_LinkedTo*1..3]->(target:CyberArk_Account)
RETURN p

// Reconcile dependencies
MATCH p=(a:CyberArk_Account)-[:CyberArk_LinkedTo {linkType: "reconcile"}]->(reconciler:CyberArk_Account)
RETURN p

// Platform-defined additional accounts (e.g. Unix JumpAccount, Cisco EnablePassword)
// resolved from platform metadata — ExtraPass2/4/… slots, not logon or reconcile
MATCH p=(a:CyberArk_Account)-[r:CyberArk_LinkedTo]->(extra:CyberArk_Account)
WHERE NOT r.linkType IN ["logon", "reconcile"]
RETURN p ORDER BY r.extraPassID

// Attack path: access a logon account, inherit every dependent account
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo]->(logon:CyberArk_Account)<-[:CyberArk_LinkedTo {linkType: "logon"}]-(dependent:CyberArk_Account)
RETURN p
```

### Safe ownership & CPM management (`CyberArk_Created`, `CyberArk_ManagedBy`)
```cypher
// Safes created by a user
MATCH p=(u:CyberArk_User)-[:CyberArk_Created]->(s:CyberArk_Safe)
RETURN p

// Who created production safes
MATCH p=(u:CyberArk_User)-[:CyberArk_Created]->(s:CyberArk_Safe)
WHERE s.safeName CONTAINS "prod"
RETURN p

// Creators who can ALSO grant themselves access (both edges rendered)
MATCH created=(u:CyberArk_User)-[:CyberArk_Created]->(s:CyberArk_Safe)
MATCH grant=(u)-[:CyberArk_CanGrantAccessTo]->(s)
RETURN created, grant

// Accounts reachable through a CPM's managed safes
MATCH p=(cpm:CyberArk_User)-[:CyberArk_ManagedBy]->(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
WHERE cpm.name CONTAINS "CPM"
RETURN p

// Safes managed by a specific CPM (inventory)
MATCH p=(cpm:CyberArk_User)-[:CyberArk_ManagedBy]->(s:CyberArk_Safe)
WHERE cpm.name CONTAINS "CPM"
RETURN p

// Safes with NO managing CPM, and the (unrotated) credentials they hold
MATCH p=(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
WHERE NOT ()-[:CyberArk_ManagedBy]->(s)
RETURN p
```

### Platforms & PSM infrastructure
```cypher
// Accounts using a specific platform
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {name: "WinServerLocal"})
RETURN p

// Platform -> PSM server routing
MATCH p=(pf:CyberArk_Platform)-[:CyberArk_UsesPSMServer]->(psm:CyberArk_PSMServer)
RETURN p

// Accounts managed by a specific PSM server
MATCH p=(a:CyberArk_Account)-[:CyberArk_ManagedByPSM]->(psm:CyberArk_PSMServer {name: "PSM Server Main"})
RETURN p

// Platforms with an RDP connection component enabled
MATCH p=(pf:CyberArk_Platform)-[:CyberArk_HasConnectionComponent]->(cc:CyberArk_ConnectionComponent {connectorId: "PSM-RDP"})
RETURN p

// PSM servers mapped to their AD Computer
MATCH p=(psm:CyberArk_PSMServer)-[:CyberArk_PSMServerHostedOn]->(c:Computer)
RETURN p

// Blast radius — every account fanning into its platform (the fan-out shows which platforms carry the most)
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform)
RETURN p

// Inactive platforms still carrying accounts
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {active: false})
RETURN p

// Platforms built from the /API/Platforms/Targets fallback (investigate /API/Platforms/ failure)
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {dataSource: "targets-fallback"})
RETURN p

// Connection-component inventory (which platforms use each connector)
MATCH p=(pf:CyberArk_Platform)-[:CyberArk_HasConnectionComponent]->(cc:CyberArk_ConnectionComponent)
RETURN p
```

### CCP / AIMWebService attack surface (`CyberArk_CanRetrieveViaCCP`)
```cypher
// Highest risk: unrestricted AppIDs that return the plaintext password via CCP
MATCH p=(app:CyberArk_Application)-[:CyberArk_CanRetrieveViaCCP {appIsUnrestricted: true, canRetrievePassword: true}]->(a:CyberArk_Account)
RETURN p

// Everything the default AIMWebService AppID can reach
MATCH p=(app:CyberArk_Application {isDefaultCCPApp: true})-[:CyberArk_CanRetrieveViaCCP]->(a:CyberArk_Account)
RETURN p

// The money shot: CCP -> credential -> Domain Admin (AppID all the way to AD)
MATCH p=(app:CyberArk_Application)-[:CyberArk_CanRetrieveViaCCP]->(a:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User)
RETURN p

// Any AppID that can retrieve a password (CCP bypasses dual control)
MATCH p=(app:CyberArk_Application)-[:CyberArk_CanRetrieveViaCCP {canRetrievePassword: true}]->(a:CyberArk_Account)
RETURN p

// Hosts from which a machine-restricted AppID can be wielded
MATCH p=(app:CyberArk_Application)-[:CyberArk_CCPAllowedFrom {machineIsOnlyRestriction: true}]->(c:Computer)
RETURN p

// Unrestricted AppIDs (no Allowed Machines / OS user / path / hash / certificate) and the credentials they reach
MATCH p=(app:CyberArk_Application {isUnrestricted: true})-[:CyberArk_CanRetrieveViaCCP]->(a:CyberArk_Account)
RETURN p

// Accounts on platforms with a wildcard AllowedSafes (audit / restrict)
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {allowedSafesIsWildcard: true})
RETURN p
```

### Cross-domain / AD correlation (external edges)
```cypher
// CyberArk account -> the AD user it maps to
MATCH p=(a:CyberArk_Account)-[:CyberArk_SyncsToADUser]->(u:User)
RETURN p

// AD user -> its CyberArk identity (LDAP sync)
MATCH p=(u:User)-[:CyberArk_SyncsToUser]->(cu:CyberArk_User)
RETURN p

// Local accounts that can connect to an AD computer
MATCH p=(a:CyberArk_Account)-[:CyberArk_CanConnect]->(c:Computer)
RETURN p

// Reachability: from a controlled CyberArk user to any AD-mapped credential (<=6 hops)
MATCH p=shortestPath((u:CyberArk_User {name: "jdoe"})-[*1..6]->(a:CyberArk_Account))
WHERE (a)-[:CyberArk_SyncsToADUser]->(:User)
RETURN p
```

### Security-finding hunting queries

These reproduce the end-of-run [Security Findings](findings.md#security-findings) summary as graph queries:
```cypher
// Unrestricted CCP applications and the credentials they reach (Critical)
MATCH p=(app:CyberArk_Application {isUnrestricted: true})-[:CyberArk_CanRetrieveViaCCP]->(a:CyberArk_Account)
RETURN p

// Credentials retrievable by unrestricted AppIDs via CCP (Critical)
MATCH p=(app:CyberArk_Application)-[:CyberArk_CanRetrieveViaCCP {appIsUnrestricted: true, canRetrievePassword: true}]->(a:CyberArk_Account)
RETURN p

// Everything the default AIMWebService application can reach (High)
MATCH p=(app:CyberArk_Application {isDefaultCCPApp: true})-[:CyberArk_CanRetrieveViaCCP]->(a:CyberArk_Account)
RETURN p

// Accounts on platforms with wildcard AllowedSafes = .* (High)
MATCH p=(a:CyberArk_Account)-[:CyberArk_UsesPlatform]->(pf:CyberArk_Platform {allowedSafesIsWildcard: true})
RETURN p

// Reconcile-account hijack paths (High): principal -> privileged reconcile account
MATCH p=(principal)-[:CyberArk_CanHijackViaReconcile]->(a:CyberArk_Account)
RETURN p

// Hosts from which a machine-only-restricted AppID can be wielded
MATCH p=(app:CyberArk_Application)-[:CyberArk_CCPAllowedFrom {machineIsOnlyRestriction: true}]->(c:Computer)
RETURN p

// PSM-routed accounts with session isolation/recording OFF, and the PSM server that brokers them (Medium)
MATCH p=(a:CyberArk_Account {managedByPSM: true})-[:CyberArk_ManagedByPSM]->(psm:CyberArk_PSMServer)
WHERE a.sessionMonitoringEnabled = false OR a.sessionRecordingEnabled = false
RETURN p

// Safes with no managing CPM, and the unrotated credentials they hold (Medium)
MATCH p=(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
WHERE s.managingCPM IS NULL OR s.managingCPM = ""
RETURN p

// Principals who can grant themselves access to a safe whose accounts they cannot use today (Medium)
MATCH p=(principal)-[:CyberArk_CanGrantAccessTo]->(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
WHERE NOT (principal)-[:CyberArk_HasAccessTo]->(a)
RETURN p

// Principals who skip the approval an account requires (Medium)
MATCH p=(principal)-[:CyberArk_HasAccessTo {bypassesApproval: true}]->(a:CyberArk_Account)
RETURN p

// Accounts that require an approval nobody in their safe can give (Medium)
MATCH p=(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account {dualControlWithoutApprovers: true})
RETURN p

// Disabled or suspended users that still hold access (Medium)
MATCH p=(u:CyberArk_User)-[:CyberArk_HasAccessTo|CyberArk_CanGrantAccessTo]->()
WHERE u.suspended = true OR u.enabled = false
RETURN p

// Accounts the CPM does not manage (Medium)
MATCH (a:CyberArk_Account {automaticManagementEnabled: false})
WHERE a.secretManagement IS NOT NULL
RETURN a

// Safe members that the user and group lists do not contain (Low)
MATCH p=(principal {placeholder: true})-[:CyberArk_HasAccessTo|CyberArk_CanGrantAccessTo]->()
WHERE principal:CyberArk_User OR principal:CyberArk_Group
RETURN p
```
