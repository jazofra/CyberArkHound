# Edge types

What each relationship in the graph means, how it is derived from CyberArk permissions, and which properties it carries.

[← Back to the README](../README.md)

## Edge Types and Permission Interpretation

The tool creates different edge types based on the permissions a user/group has on a safe:

> **Looking for the Cypher?** Every query for the edges and findings described below is collected in one place — see the [BloodHound Cypher Query Library](queries.md#bloodhound-cypher-query-library). Wherever a query traverses a relationship it is written to return the **full path** (`MATCH p=… RETURN p`) so BloodHound draws the attack path, not just its endpoints.

### CyberArk_HasAccessTo (User/Group → Account)
**Direct account access** - User/group can immediately use or retrieve account credentials:
- `useAccounts`: Use accounts via PSM connections without viewing passwords
- `retrieveAccounts`: Retrieve and view account passwords

**Pattern**: When a user has these permissions on a safe, edges are created from the user directly to **each account** in that safe. This clearly shows which accounts the user can access.

_Queries: [Direct account access](queries.md#direct-account-access-cyberark_hasaccessto)._

### CyberArk_CanGrantAccessTo (User/Group → Safe)
**Privilege escalation** - User/group can modify safe to grant themselves account access:
- `manageSafe`: Update safe properties, recover safe, delete safe
- `manageSafeMembers`: Add/remove safe members and modify their permissions

**Attack path**: A user with `manageSafeMembers` can add themselves with `retrieveAccounts`, then access all accounts in the safe. This edge points to the **safe** itself since the user must first escalate privileges before accessing accounts.

_Queries: [Privilege escalation](queries.md#privilege-escalation-cyberark_cangrantaccessto)._

### Edge Types Summary

| Edge | Direction | Pathfinding | Source | Security Value |
|------|-----------|-------------|--------|----------------|
| `CyberArk_HasAccessTo` | User/Group → Account | Traversable (solid) | Safe member `useAccounts`/`retrieveAccounts` | Direct credential access; `requiresApproval` shows if dual control blocks retrieval |
| `CyberArk_CanRetrieveViaCCP` | Application → Account | Traversable (solid) | Application safe member `useAccounts`/`retrieveAccounts` + `GET /WebServices/PIMServices.svc/Applications` | CCP/AIMWebService credential retrieval via a single GET request; `appIsUnrestricted` and `isDefaultCCPApp` flag the highest-risk AppIDs ([Nigmatullin, SO-CON 2026](ccp-tradecraft.md#tradecraft-reference)) |
| `CyberArk_CCPAllowedFrom` | Application → AD Computer | Non-traversable (dashed) | Application `machineAddress` authentications (Allowed Machines) | External edge — which hosts may present the AppID to CCP; `machineIsOnlyRestriction` flags when landing on the host is sufficient to wield the AppID |
| `CyberArk_CanGrantAccessTo` | User/Group → Safe | Traversable (solid) | Safe member `manageSafe`/`manageSafeMembers` | Privilege escalation — can grant themselves account access |
| `CyberArk_CanHijackViaReconcile` | User/Group → Account | Traversable (solid) | Safe member `addAccounts`/`manageSafe` + reconcile linked account (`GET /API/Accounts/{id}/LinkedAccounts`) | Privilege escalation — can coerce the CPM to reset a target's password using a privileged reconcile account ([Nigmatullin, SO-CON 2026](ccp-tradecraft.md#tradecraft-reference)) |
| `CyberArk_CanApprove` | User/Group → Safe | Non-traversable (dashed) | Safe member `requestsAuthorizationLevel1`/`Level2` | Can approve dual-controlled access requests (L1/L2) |
| `CyberArk_UsedAccount` | User → Account | Non-traversable (dashed) | `GET /API/Accounts/{id}/Activities` | Actual usage audit trail — who really accessed what |
| `CyberArk_LinkedTo` | Account → Account | Non-traversable (dashed) | `GET /API/Accounts/{id}/LinkedAccounts` | Logon/reconcile/additional credential chains — compromising the linked account propagates to all its dependents, against the edge direction (hence non-traversable) |
| `CyberArk_Created` | User → Safe | Non-traversable (dashed) | Existing `Safe.Creator` field | Shows who created each safe (implicit ownership/access) |
| `CyberArk_ManagedBy` | CPM User → Safe | Traversable (solid) | Existing `Safe.ManagingCPM` field | CPM accounts have privileged password management access |
| `CyberArk_UsesPlatform` | Account → Platform | Non-traversable (dashed) | `GET /API/Platforms/Targets` | Shared platform config = shared attack surface |
| `CyberArk_UsesPSMServer` | Platform → PSM Server | Non-traversable (dashed) | Platform `PSMServerID` field | Which PSM server handles sessions for each platform |
| `CyberArk_ManagedByPSM` | Account → PSM Server | Non-traversable (dashed) | Derived via account's platform | Direct link for querying which PSM server manages an account's sessions |
| `CyberArk_HasConnectionComponent` | Platform → Connection Component | Non-traversable (dashed) | `GET /API/Platforms/Targets/{id}/PrivilegedSessionManagement` | Which connection protocols (RDP, SSH, etc.) are enabled per platform |
| `CyberArk_PSMServerHostedOn` | PSM Server → AD Computer | Non-traversable (dashed) | PSM Server `Address` field (uppercased) | External edge — maps PSM server to its AD Computer object |
| `CyberArk_MemberOf` | User/Group → Group | Traversable (solid) | Group membership data | Group-based permission inheritance |
| `CyberArk_Contains` | Safe → Account | Traversable (solid) | Account's `safeName` field | Safe-account containment relationship |
| `CyberArk_InstanceContains` | Instance → Safe/Platform/PSM Server/Connection Component | Non-traversable (dashed) | Derived (one root per PVWA tag) | Environment root containment — scopes bounded configuration objects to their PVWA instance. Users and groups are excluded to avoid a multi-million-edge fan-out in LDAP-synced vaults |
| `CyberArk_SyncsToUser` | AD User → CyberArk_User | Traversable (solid) | LDAP DN with `DC=` | External edge — AD-to-CyberArk identity mapping |
| `CyberArk_SyncsToGroup` | AD Group → CyberArk_Group | Traversable (solid) | LDAP DN with `DC=` | External edge — AD-to-CyberArk group mapping |
| `CyberArk_SyncsToADUser` | CyberArk_Account → AD User | Traversable (solid) | Account address matches target domain | External edge — credential-to-AD-user mapping |
| `CyberArk_CanConnect` | CyberArk_Account → AD Computer | Traversable (solid) | Account address matches address subdomain of the target domain (Local accounts) | External edge — credential-to-AD-computer mapping |

**Note**: Permissions like `listAccounts`, `viewAuditLog`, `addAccounts`, `updateAccountContent` do **not** create access edges as they don't allow password retrieval or account usage.

**Pathfinding column**: BloodHound only follows **traversable** edges when it computes paths and Attack Path findings, and its Explore graph draws them as solid lines. **Non-traversable** edges are drawn dashed and never appear in a computed path. They are still in the graph, so explicit Cypher queries (like everything in the [query library](queries.md#bloodhound-cypher-query-library)) still return them. An edge is traversable only when controlling its source gives the attacker its target. See [Traversable vs non-traversable edges](bloodhound-extension.md#traversable-vs-non-traversable-edges-solid-vs-dashed) for the reasoning behind each decision.

### CyberArk_UsedAccount (User → Account) - Optional
**Actual account usage** - Tracks when users have actually retrieved or used accounts (not just permission):
- Created when `--include-activity` flag is used
- Based on CyberArk activity/audit logs via `/API/Accounts/{accountId}/Activities`
- Shows real-world account access patterns from the last 3 days (default)
- Helps identify dormant vs actively used accounts
- One edge per user-account pair (aggregates multiple activities)

**Pattern**: Edges are created from users to accounts they've actually accessed within the specified time window (`--activity-days`). Multiple activities by the same user are aggregated into a single edge showing the most recent action.

**Edge Properties**:
- `lastUsedTime`: ISO 8601 timestamp of most recent access (e.g., "2025-11-25T14:32:01Z")
- `lastActivity`: Most recent action performed (e.g., "CPM Verify Password", "RetrievePassword", "ShowPassword")
- `usageCount`: Total number of activities this user performed on this account in the time window
- `retrieveCount`: How many of them showed, copied or retrieved the password
- `connectCount`: How many of them opened a session with the account (e.g. through PSM)
- `cpmCount`: How many of them were CPM operations (verify, change, reconcile)
- `credentialAccess`: `true` if a person retrieved the password or connected with the account at least once (`retrieveCount + connectCount > 0`). The CPM user's housekeeping produces edges with `credentialAccess: false`; filter on this property to see people only
- `inferred`: false (based on actual audit data)

**Technical Details**:
- Activities are filtered by Unix timestamp (Date field >= current_time - days * 86400)
- Only activities within the lookback window are processed
- If a user performed multiple actions, only the most recent is stored in `lastActivity`
- The `usageCount` reflects all qualifying activities, not just the latest one
- Activities are sorted into retrieve / connect / CPM by their action text. Action texts vary between PVWA versions and languages, so an action that is not recognised counts towards `usageCount` only
- Parallel processing used for activity fetching (50 workers by default)

_Queries: [Actual usage / activity](queries.md#actual-usage--activity-cyberark_usedaccount)._

**Performance Note**: Activity tracking adds significant API calls (one per account). For large environments (1000+ accounts), expect:
- Additional 5-15 minutes processing time due to parallel API requests
- Default lookback is 3 days to balance recency with performance
- Use `--activity-days 7` or `--activity-days 30` for longer historical analysis
- Use `--activity-limit` to cap activities fetched per account (default: 100)
- Activity fetching runs in parallel (50 threads) for optimal performance
- Can be run separately from initial data collection for incremental updates

### Dual Control (Access Confirmation) Awareness
CyberArk's dual control feature requires users to get approval from authorized Safe members before retrieving passwords. CyberArkHound determines dual control status using a combination of platform policy data and safe member permissions.

**How CyberArk Dual Control works:**

Dual control is governed by the **Master Policy** rule "Require dual control password access approval", which can be set globally or overridden per platform. The effective policy for each platform is exposed via the `GET /API/Platforms/` endpoint in the `privilegedAccessWorkflows.requireDualControlPasswordAccessApproval` field. Safe members with `requestsAuthorizationLevel1` or `requestsAuthorizationLevel2` permissions act as the **approvers** who confirm or reject access requests.

**How CyberArkHound determines `requiresApproval`:**

The `requiresApproval` property on `CyberArk_HasAccessTo` edges is computed **per-account** using a layered approach:

| Layer | Source | Check |
|-------|--------|-------|
| 1. Platform policy (primary) | `GET /API/Platforms/` → `requireDualControlPasswordAccessApproval` | Is dual control enabled for the account's platform in the effective Master Policy? |
| 2. Approver presence (enforcement) | Safe member permissions → `requestsAuthorizationLevel1` / `Level2` | Does the safe have at least one member who can approve requests? Without approvers, dual control is unenforceable even if the policy enables it. |
| 3. Member bypass | Safe member permissions → `accessWithoutConfirmation` | Can this specific member bypass dual control? If `true`, `requiresApproval` is always `false`. |

An account's `requiresApproval` is `true` only when **all three conditions** are met:
1. The account's platform has `requireDualControlPasswordAccessApproval: true`
2. The safe has at least one member with L1/L2 approval permissions
3. The accessing member does **not** have `accessWithoutConfirmation: true`

**Fallback when platform data is unavailable:**
When `--include-platforms` is not used, the platform policy cannot be checked. In this case, CyberArkHound falls back to an **approver-presence heuristic**: if the safe has members with L1/L2 approval permissions, dual control is assumed to be active. This can produce false positives (e.g., approver permissions exist from a template but the Master Policy has dual control disabled). Use `--include-platforms` for accurate dual control detection.

**CyberArk safe member permissions used:**

| Permission | Type | Role |
|------------|------|------|
| `accessWithoutConfirmation` | bool | Member can bypass dual control and retrieve passwords without approval |
| `requestsAuthorizationLevel1` | bool | Member can approve Level 1 access requests from other users |
| `requestsAuthorizationLevel2` | bool | Member can approve Level 2 access requests from other users |

**Platform policy field used (requires `--include-platforms`):**

| Field | Source | Meaning |
|-------|--------|---------|
| `requireDualControlPasswordAccessApproval` | `GET /API/Platforms/` → `privilegedAccessWorkflows` | The effective Master Policy setting for this platform, including any platform-level exceptions |

**Edge Properties on CyberArk_HasAccessTo:**
- `requiresApproval`: `true` if the member needs approval from a dual control authorizer before retrieving passwords
- `bypassesApproval`: `true` if dual control applies to the account but this member skips it through `accessWithoutConfirmation`. Present only when true
- `requiresSessionMonitoring`: `true` if the account's platform requires PSM session monitoring and isolation
- `recordsSessionActivity`: `true` if the account's platform records and saves session activity

**CyberArk_CanApprove Edge Properties:**
- `approvalLevel`: Authorization level (1 or 2) — maps to `requestsAuthorizationLevel1` / `requestsAuthorizationLevel2` permissions

_Queries: [Dual control (approval) analysis](queries.md#dual-control-approval-analysis) and [Platforms & PSM infrastructure](queries.md#platforms--psm-infrastructure)._

### CyberArk_LinkedTo (Account → Account) - Optional
**Linked account dependencies** - Maps credential chains where one account depends on another for logon, reconciliation, or a platform-defined additional role:
- Created when `--include-linked-accounts` flag is used
- Based on the linked accounts returned with the account details (`/API/Accounts/{accountId}`)
- Link types: `logon` (ExtraPass1) and `reconcile` (ExtraPass3) are fixed roles. Every other slot (ExtraPass2, ExtraPass4, …) is a platform-defined **additional** account whose real type name is resolved positionally from the platform's `linkedAccounts` metadata — e.g. a Unix `JumpAccount` or a Cisco `EnablePassword`. When platform metadata isn't collected, additional slots fall back to the generic label `additional`.
- Critical for attack path analysis: compromising a logon account gives access to all accounts that depend on it, and a reconcile account can reset every account that names it
- **Non-traversable (dashed in BloodHound)**: the edge points from the dependent account to the account it depends on, but control runs the other way. Holding the dependent account's password does not reveal its logon or reconcile account. If the edge were traversable, pathfinding would report false paths like "access to any account leads to its Domain Admin reconcile account". To find a linked account's real blast radius, start from the linked account, as the [linked-account queries](queries.md#linked-account--credential-chains-cyberark_linkedto) do.

**Edge Properties**:
- `linkType`: Resolved type of link — `logon`, `reconcile`, the platform-defined type name (e.g. `JumpAccount`, `EnablePassword`), or `additional` when platform metadata is unavailable
- `linkTypeDisplayName`: Human-readable display name for the link type (from platform metadata when available)
- `extraPassID`: Raw CyberArk extra-password slot number (1=logon, 3=reconcile, others=additional)
- `linkName`: Name of the linked account relationship
- `safeName`: Safe containing the linked account

_Queries: [Linked account / credential chains](queries.md#linked-account--credential-chains-cyberark_linkedto)._

**Performance Note**: Linked account fetching adds one API call per account. Runs in parallel (50 workers by default).

### CyberArk_Created (User → Safe)
**Safe creator relationship** - Shows which user created each safe:
- Always emitted (no extra API calls — uses existing `Safe.Creator` field)
- Useful for understanding implicit access and ownership

**Edge Properties**:
- `creatorId`: The vault user ID of the creator

_Queries: [Safe ownership & CPM management](queries.md#safe-ownership--cpm-management-cyberark_created-cyberark_managedby)._

### CyberArk_ManagedBy (CPM User → Safe)
**CPM management relationship** - Shows which CPM component manages password rotation for each safe:
- Always emitted (no extra API calls — uses existing `Safe.ManagingCPM` field)
- CPM accounts have privileged access to manage and rotate passwords

_Queries: [Safe ownership & CPM management](queries.md#safe-ownership--cpm-management-cyberark_created-cyberark_managedby)._

### CyberArk_UsesPlatform (Account → Platform) - Optional
**Platform association** - Shows which platform configuration each account uses:
- Created when `--include-platforms` flag is used
- Creates `CyberArk_Platform` nodes from `/API/Platforms/Targets`
- Accounts sharing a platform share configuration, policies, and potential vulnerabilities

_Queries: [Platforms & PSM infrastructure](queries.md#platforms--psm-infrastructure)._

### CyberArk_CanRetrieveViaCCP (Application → Account) - Optional
**CCP / AIMWebService credential retrieval** - Maps which credentials each CyberArk Application (AppID) can pull through the Central Credential Provider REST API:
- Created when `--include-applications` flag is used
- Built from the application's safe membership (`useAccounts`/`retrieveAccounts`) combined with the Applications list from `GET /WebServices/PIMServices.svc/Applications`
- This is the credential-access path used by automated workflows (CI/CD runners, scripts, services) — and the focus of the tradecraft described in [Marat Nigmatullin's SO-CON 2026 talk](ccp-tradecraft.md#tradecraft-reference)

**Edge Properties**:
- `canRetrievePassword`: `true` when the application has `retrieveAccounts` (CCP returns the plaintext password); `false` when only `useAccounts`
- `appIsUnrestricted`: `true` when the AppID has **no** authentication restriction (no Allowed Machines and no OS user / path / hash / certificate binding) — knowing the AppID alone is enough to retrieve the credential from anywhere that can reach the CCP endpoint
- `isDefaultCCPApp`: `true` for the out-of-the-box `AIMWebService` AppID, which usually has access to **all** safes
- `allowedMachines`: list of IPs/hosts permitted to use the AppID (empty when unrestricted)
- `safeName`, `permissions`: the safe and the granted permission names

_Queries: [CCP / AIMWebService attack surface](queries.md#ccp--aimwebservice-attack-surface-cyberark_canretrieveviaccp)._
