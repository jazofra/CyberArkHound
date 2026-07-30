// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

// NodeInfo holds curated, security-relevant documentation for a BloodHound node
// kind, modeled after the per-edge EdgeInfo metadata. It is the single source of
// truth for the schema-level Entity Panel "info" sections rendered for each
// CyberArk node kind (see extension/schema.json and BuildSchemaJSON).
//
// The Overview / Abuse / OpsecNotes fields are markdown; Abuse may embed fenced
// code blocks. References are rendered as a markdown link list.
type NodeInfo struct {
	Overview   string
	Abuse      string
	OpsecNotes string
	References []string
}

// NodeInfoMap contains Entity Panel documentation for all CyberArkHound node
// kinds. Keys must be canonical node kinds (see graph.NodeKinds); the drift
// guard in schema_test.go enforces this.
var NodeInfoMap = map[string]NodeInfo{
	"CyberArk_Instance": {
		Overview: "A CyberArk PVWA/Vault instance — the top-level container for everything CyberArkHound collected from a single PVWA: users, groups, safes, accounts, platforms, PSM infrastructure, and applications (AppIDs). " +
			"Each instance is namespaced by the 4-character PVWA tag derived from the `--pvwa` URL, so multiple vaults can coexist in one BloodHound database without colliding. " +
			"The instance is the environment node for the CyberArk source and the anchor for scoping queries to a single deployment.",
		Abuse: "The instance node is structural and is not itself an attack target. Use it to scope traversals to one vault and to pivot into the high-value objects it contains:\n\n" +
			"- Follow `CyberArk_InstanceContains` to enumerate the safes, platforms, PSM servers, and connection components of this deployment.\n" +
			"- From there, chase `CyberArk_HasAccessTo`, `CyberArk_CanGrantAccessTo`, and `CyberArk_CanRetrieveViaCCP` to reach credentials.\n" +
			"- Compromise of the PVWA host or Vault server itself is a full-environment compromise: the Vault holds every managed credential, and PVWA brokers all interactive access.",
		OpsecNotes: "Enumeration of the vault's structure via the REST API is generally low-signal, but authenticating to PVWA and listing safes/accounts is recorded in the CyberArk audit trail under the acting user. " +
			"Direct access to the Vault or PVWA servers is a critical security event that typically triggers incident response.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/the-privileged-access-security-solution.htm",
		},
	},
	"CyberArk_User": {
		Overview: "A CyberArk Vault user. May be a local EPV user, a component/service account (CPM, PSM, PVWA), or an LDAP/directory-synced user. " +
			"Users hold safe permissions directly or inherit them through `CyberArk_MemberOf` group membership, and directory-synced users are bridged to Active Directory via `CyberArk_SyncsToUser`. " +
			"Key properties include whether the user is enabled/suspended, a component user, and its authentication source.",
		Abuse: "A user is a principal: its reachable credentials are the union of its own and its groups' outgoing edges.\n\n" +
			"- Follow `CyberArk_HasAccessTo` for accounts whose passwords the user can retrieve, and `CyberArk_CanGrantAccessTo` for safes where the user can add itself (or a controlled account) with retrieve permission.\n" +
			"- `CyberArk_CanApprove` marks dual-control approval authority — combined with `CyberArk_HasAccessTo` on the same safe it enables self-approval.\n" +
			"- Directory-synced users (`CyberArk_SyncsToUser`) are reachable from the AD side: compromising the mapped AD principal grants the Vault user's access via LDAP logon.\n" +
			"- Component users (CPM/PSM/PVWA) are among the most privileged identities in the deployment; treat them as high-value.",
		OpsecNotes: "Interactive and API logons under a user are recorded in the Vault audit trail; LDAP-backed logons also generate Active Directory authentication events. " +
			"Repeated failed logons may trip account-lockout policy. Component-user activity that deviates from its normal automated pattern is a strong detection opportunity.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/managing-users.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/ldap-integration.htm",
		},
	},
	"CyberArk_Group": {
		Overview: "A CyberArk Vault group. Members — users or nested groups — inherit all safe permissions and vault authorizations granted to the group cumulatively. " +
			"A group may be local to the vault or synchronized from a directory, in which case `CyberArk_SyncsToGroup` bridges it to an Active Directory group and AD membership changes propagate on the next LDAP sync.",
		Abuse: "Groups concentrate access: a single membership can confer credential access across many safes.\n\n" +
			"- Enumerate the group's outgoing `CyberArk_HasAccessTo` / `CyberArk_CanGrantAccessTo` / `CyberArk_CanApprove` edges to see the effective blast radius of membership.\n" +
			"- Adding a controlled principal via `CyberArk_MemberOf` (or, for a synced group, into the mapped AD group) inherits all of that access — often a stealthier path than modifying safe membership directly.\n" +
			"- Directory-synced groups are a cross-surface escalation: an AD group edit lands as CyberArk access after the sync interval, with no direct change inside the vault.",
		OpsecNotes: "Vault group-membership reads via the REST API are generally not audited. Effective access through a group may not appear in safe-membership reports that list the group rather than its members. " +
			"AD group edits on synced groups generate Windows events (4728/4732/4756) and take effect only after CyberArk's LDAP sync cycle, creating a detectable delay window.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/managing-vault-groups.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/configuring-directory-mappings.htm",
		},
	},
	"CyberArk_Safe": {
		Overview: "A CyberArk safe — a logical container holding privileged accounts and their credentials. Safe members hold permissions (use, retrieve, list, manage members, approve) that govern credential access and privilege escalation. " +
			"The `managingCPM` property names the CPM that rotates the safe's credentials; a blank value (surfaced as the `SAFE_NO_CPM` finding) means the safe's passwords are not being automatically managed.",
		Abuse: "The safe is the unit of access control — most CyberArk attack paths pass through one.\n\n" +
			"- `CyberArk_Contains` links the safe to its accounts; combine with the principals' `CyberArk_HasAccessTo` edges to map who can reach which credentials.\n" +
			"- `CyberArk_CanGrantAccessTo` into the safe is a privilege-escalation primitive: a member with manageSafe/manageSafeMembers can add itself with retrieveAccounts and read every account inside.\n" +
			"- `CyberArk_CanApprove` on the safe governs dual-control; watch for principals that can both request and approve access to the same safe.\n" +
			"- A safe without a managing CPM often holds stale, unrotated, or manually-managed credentials that may already be known or reused.",
		OpsecNotes: "Safe membership additions and permission changes are logged in the Vault audit trail and appear immediately in PVWA safe management; SIEM integrations may alert in real time. " +
			"Reusing an already-present compromised member is quieter than adding a new one. Account enumeration within a safe requires ListAccounts and is audited.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/dv-managing-safes.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safe-members-add.htm",
		},
	},
	"CyberArk_Account": {
		Overview: "A privileged account stored in a CyberArk safe — a managed credential for a target system, domain user, or local machine account. " +
			"Principals with retrieveAccounts can obtain the plaintext password; principals with useAccounts can launch a PSM-brokered session without ever seeing it. " +
			"Inferred edges link the account outward: `CyberArk_SyncsToADUser` (the credential belongs to an AD user), `CyberArk_CanConnect` (it authenticates to an AD computer, often as local admin), and `CyberArk_LinkedTo` (logon/reconcile/additional dependencies). " +
			"Session properties such as `managedByPSM`, `sessionMonitoringEnabled`, and `sessionRecordingEnabled` describe how tightly the account's use is brokered.",
		Abuse: "The account is the credential — retrieving it is usually the objective.\n\n" +
			"```powershell\n" +
			"# Requires retrieveAccounts on the containing safe:\n" +
			"Invoke-RestMethod -Uri \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" `\n" +
			"    -Method POST -Headers @{Authorization = \"Bearer $token\"} -Body '{}' -ContentType 'application/json'\n" +
			"```\n\n" +
			"- Follow `CyberArk_SyncsToADUser` / `CyberArk_CanConnect` to turn a retrieved credential into AD authentication or lateral movement to a specific host.\n" +
			"- A retrievable account can also be reached indirectly through CCP (`CyberArk_CanRetrieveViaCCP` from an AppID) or through a reconcile hijack (`CyberArk_CanHijackViaReconcile`), each of which bypasses interactive PVWA login.\n" +
			"- If the account is `managedByPSM` but monitoring or recording is disabled (the `PSM_BREAKOUT_EXPOSURE` finding), a brokered session is an easier target for escape.",
		OpsecNotes: "Every password retrieval and PSM session start is logged in the Vault audit trail under the requesting user. If the account requires approval, retrieval without an approved request is denied and the request itself is visible to approvers. " +
			"Subsequent use of the credential in Active Directory generates standard Windows authentication events (4624/4648/4768/4769/4776) that can be correlated with the prior vault retrieval.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccountpasswordvalue.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/configuring-accounts.htm",
		},
	},
	"CyberArk_Platform": {
		Overview: "A CyberArk platform definition governing password policy, connection settings, dual-control requirements, PSM routing, and Master Policy exception flags. " +
			"All accounts sharing a platform share the same security baseline, so a single platform-level exception weakens every account on it at once. " +
			"The `allowedSafesIsWildcard` property flags a platform whose AllowedSafes is `.*` (the `PLATFORM_WILDCARD_ALLOWEDSAFES` finding), letting its accounts be created in any safe.",
		Abuse: "Platforms are policy, and policy exceptions are the attack surface.\n\n" +
			"```powershell\n" +
			"# Inspect a platform for weakened controls:\n" +
			"Invoke-RestMethod -Uri \"https://<pvwa>/PasswordVault/API/Platforms/<platformId>\" `\n" +
			"    -Headers @{Authorization = \"Bearer $token\"}\n" +
			"# Red flags: RequireDualControlPasswordAccessApproval=false, EnforceCheckinCheckoutExclusiveAccess=false\n" +
			"```\n\n" +
			"- `CyberArk_UsesPlatform` (from accounts) and `CyberArk_HasConnectionComponent` / `CyberArk_UsesPSMServer` (to session infrastructure) reveal which accounts inherit the platform's policy and how their sessions are brokered.\n" +
			"- A platform that defines a privileged reconcile account underpins `CyberArk_CanHijackViaReconcile`: anyone able to add accounts on it can coerce the CPM into resetting a target of their choosing.\n" +
			"- A wildcard AllowedSafes lets an attacker with account-creation rights stage accounts anywhere, broadening reconcile-hijack and CCP reach.",
		OpsecNotes: "Reading platform configuration is non-invasive and generally not audited. Platform modifications require Vault Administrator-level privileges and are logged; unexpected reassignment of high-value accounts to a weaker platform is a strong detection signal.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/manage-platforms.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/master-policy.htm",
		},
	},
	"CyberArk_PSMServer": {
		Overview: "A Privileged Session Manager server that brokers, isolates, and records privileged sessions. It acts as a proxy between the requesting user and the target system, holding the managed credential on the user's behalf so the plaintext is never exposed to the client. " +
			"`CyberArk_UsesPSMServer` / `CyberArk_ManagedByPSM` map which platforms and accounts route through it, and `CyberArk_PSMServerHostedOn` correlates it to the Active Directory computer it runs on.",
		Abuse: "Compromising a PSM server exposes every session it processes — live, in-flight sessions and stored recordings alike.\n\n" +
			"- PSM for Windows stores session recordings locally before transfer (default `C:\\ProgramData\\CyberArk\\PSM\\Sessions\\`); PSM for SSH (PSMP) runs on Linux under `/opt/CARKpsmp/` with logs in `/var/opt/CARKpsmp/logs/`.\n" +
			"- Follow `CyberArk_PSMServerHostedOn` to the underlying host and pivot via its normal Windows/Linux attack surface (RDP, WinRM, SSH).\n" +
			"- Because PSM authenticates to targets internally, control of the server can yield reuse of the credentials flowing through it and the ability to break out of the brokered session toward the target system.",
		OpsecNotes: "PSM servers are high-value, typically hardened and heavily monitored. All brokered sessions are logged with full metadata and content recording, and access to the PSM host is usually restricted to infrastructure administrators — direct access is conspicuous.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/manage-psm-for-windows.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/psm-manage-recordings.htm",
		},
	},
	"CyberArk_ConnectionComponent": {
		Overview: "A PSM connection component defining a session protocol available for accounts on a platform — e.g. PSM-RDP (Remote Desktop), PSM-SSH (Secure Shell), PSM-Telnet, or PSM-WebApp. " +
			"`CyberArk_HasConnectionComponent` links a platform to the components it has enabled, which determines the protocols an operator (or attacker) can use when initiating a PSM-brokered session.",
		Abuse: "Connection components are informational for pathing but reveal capability and target type.\n\n" +
			"- An enabled RDP component (e.g. PSM-RDP) implies Windows targets and interactive desktop sessions without exposing the password; an SSH component implies Unix/Linux hosts or network devices via PSMP.\n" +
			"- Combined with `useAccounts` on an account (`CyberArk_HasAccessTo`), the available components dictate how you can connect through PSM:\n\n" +
			"```powershell\n" +
			"$body = @{Reason = 'authorized'; ConnectionComponent = 'PSM-RDP'} | ConvertTo-Json\n" +
			"Invoke-RestMethod -Uri \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/PSMConnect\" `\n" +
			"    -Method POST -Headers @{Authorization = \"Bearer $token\"} -Body $body -ContentType 'application/json'\n" +
			"```",
		OpsecNotes: "All connection-component sessions are fully logged and recorded by PSM, with keystroke logging and screen capture depending on platform configuration. The component in use also discloses the target system type to defenders reviewing session records.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/cc-about-connection-components.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/psm-connect.htm",
		},
	},
	"CyberArk_Application": {
		Overview: "A CyberArk Application (AppID) used with the Central Credential Provider (CCP / AIMWebService) or Credential Provider (CP) to retrieve credentials from the Vault at runtime via REST. " +
			"The `isUnrestricted` property flags an AppID with no authentication binding (no Allowed Machines, OS user, path, hash, or certificate) — knowledge of the AppID alone is enough to pull its credentials. " +
			"`isDefaultCCPApp` flags the out-of-the-box AIMWebService application, which usually has access to every safe. " +
			"Tradecraft: Marat Nigmatullin (@_mnigma_, FalconForce), \"4 GET requests = 3 Domain admins: CyberArk magic you didn't know about\", SO-CON 2026.",
		Abuse: "An unrestricted AppID is a credential-retrieval oracle reachable by anyone who can hit the CCP endpoint.\n\n" +
			"```bash\n" +
			"# Exact retrieval of one account:\n" +
			"curl -s \"https://<CCP>/AIMWebService/api/Accounts?AppID=<AppID>&Safe=<safe>&UserName=<user>&Address=<addr>\"\n" +
			"# RegExp sweep (one match per request):\n" +
			"curl -s \"https://<CCP>/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=adm\"\n" +
			"# The default AIMWebService AppID usually reads every safe:\n" +
			"curl -s \"https://<CCP>/AIMWebService/api/Accounts?AppID=AIMWebService&QueryFormat=regexp&Query=username=admin\"\n" +
			"```\n\n" +
			"- Follow `CyberArk_CanRetrieveViaCCP` to see exactly which accounts the AppID can pull; the `CCP_UNRESTRICTED_APP`, `CCP_UNRESTRICTED_RETRIEVAL`, and `CCP_DEFAULT_AIMWEBSERVICE` findings pre-rank the highest-value targets.\n" +
			"- If the AppID is restricted to Allowed Machines, `CyberArk_CCPAllowedFrom` points at the hosts that satisfy the restriction — landing on one of those hosts is enough when `machineIsOnlyRestriction` is true.\n" +
			"- CI/CD runners that hold an AppID are a common foothold for reaching the CCP endpoint.",
		OpsecNotes: "CCP retrievals sit outside the interactive PVWA workflow and are not subject to dual-control approval, so a successful pull raises no approval request. Usage is still recorded (Provider logs plus the Vault audit trail under the application identity). " +
			"Because each request returns at most one match, RegExp sweeps are noisy — responses like \"Too many password objects\" flag over-broad queries. Prefer exact Safe/Object/UserName lookups to stay quiet.",
		References: []string{
			"https://docs.cyberark.com/credential-providers/latest/en/content/ccp/calling-the-web-service-using-rest.htm",
			"https://docs.cyberark.com/credential-providers/latest/en/content/cp%20and%20ascp/application-details.htm",
			"https://github.com/SpecterOps/presentations/tree/main/SO-CON%202026",
		},
	},
}
