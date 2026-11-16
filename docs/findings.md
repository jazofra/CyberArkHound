# Security findings

The misconfigurations CyberArkHound reports at the end of a run, and how to validate and fix each one.

[← Back to the README](../README.md)

## Security Findings

At the end of each run, CyberArkHound logs a **Security Findings** summary derived entirely from the collected data (no extra API calls), so the highest-value misconfigurations surface without writing any Cypher:

| Finding | Severity | Source |
|---------|----------|--------|
| Unrestricted CCP applications (AppIDs) | Critical | `CyberArk_Application.isUnrestricted` |
| Credentials retrievable by unrestricted AppIDs via CCP | Critical | `CyberArk_CanRetrieveViaCCP` (`appIsUnrestricted` + `canRetrievePassword`) |
| Default AIMWebService application present | High | `CyberArk_Application.isDefaultCCPApp` |
| Platforms with wildcard AllowedSafes (`.*`) | High | `CyberArk_Platform.allowedSafesIsWildcard` |
| Reconcile-account hijack paths | High | `CyberArk_CanHijackViaReconcile` edges |
| PSM-routed accounts without session isolation/recording | Medium | `CyberArk_Account.managedByPSM` + `sessionMonitoringEnabled`/`sessionRecordingEnabled` |
| Principals who can grant themselves access they do not have | Medium | `CyberArk_CanGrantAccessTo` on a safe without `CyberArk_HasAccessTo` to its accounts |
| Principals who bypass dual-control approval | Medium | `CyberArk_HasAccessTo.bypassesApproval` |
| Dual control required but the safe has no approvers | Medium | `CyberArk_Account.dualControlWithoutApprovers` |
| Disabled or suspended users that still hold access | Medium | `CyberArk_User.enabled` / `suspended` + access or grant edges |
| Accounts with automatic management disabled | Medium | `CyberArk_Account.automaticManagementEnabled` false |
| Safes without CPM management | Medium | `CyberArk_Safe.managingCPM` empty |
| Safe members missing from the user and group lists | Low | placeholder `CyberArk_User`/`CyberArk_Group` with access or grant edges |

Three of these are judged only when the data to judge them is present, so that a gap in the collection is not reported as a misconfiguration: disabled users are reported only when this PVWA returned the `enabled` flag for its users, unmanaged accounts only when the account's secret-management state was returned, and missing approvers only for safes whose members were collected.

Only findings with a non-zero count are shown. For full coverage, run with `--include-applications` and `--include-platforms` (both default-on). An application whose authentication restrictions could not be read is marked `authenticationsUnknown` and is never counted as unrestricted.

`--fail-on <severity>` makes the run exit with code 3 when any finding is at least that severe.

`--findings-output` writes the findings to a file, in the format its extension asks for or the one given with `--findings-format`:

| Format | Extension | Contents |
|--------|-----------|----------|
| `json` | any other | The full report, shown below |
| `sarif` | `.sarif` | SARIF 2.1.0 for code-scanning and vulnerability-management tools: one rule per finding, one result per object, with the vault objects as logical locations |
| `csv` | `.csv` | One row per object: `finding_id, severity, title, object_id, object_name, target_id, target_name` |
| `markdown` | `.md` | A readable summary with the first 100 objects of each finding |

With `--findings-output findings.json`, the same findings are also written as JSON, each listing the objects behind it (node `id` and `name`; for relationship-based findings also the `target` and `targetName`), together with the collection's `incomplete` reasons:

```json
{
  "generatedAt": "2026-10-05T09:00:00Z",
  "collectedAt": "2026-10-05T08:12:44Z",
  "pvwaUrl": "https://pvwa.example.com",
  "pvwaTag": "PVEX",
  "findings": [
    {
      "id": "SAFE_NO_CPM",
      "title": "Safes without CPM management",
      "severity": "Medium",
      "count": 1,
      "detail": "Safes with no managing CPM do not have automated password rotation; stored credentials may be stale or unrotated.",
      "objects": [{ "id": "CASAFE-LEGACY-PVEX", "name": "Legacy" }]
    }
  ]
}
``` The CCP-related findings map the tradecraft documented by [Marat Nigmatullin (SO-CON 2026)](ccp-tradecraft.md#tradecraft-reference).

**Equivalent hunting queries (BloodHound):** these are collected in the [Cypher Query Library → Security-finding hunting queries](queries.md#security-finding-hunting-queries), alongside the full path-form query catalogue for every edge type.

> **Note on `relationship_findings` in `extension/schema.json`:** BloodHound's findings/remediation are an Enterprise-only feature and the exact `relationship_findings` schema shape is not publicly documented, so that array is intentionally left empty rather than populated with an unverified structure that could break ingestion. The findings above are computed and surfaced at collection time instead.

## Validating & Exploiting Findings

> ⚠️ **Authorized testing only.** Everything below is for use during a sanctioned penetration test, red-team engagement, or your own lab. Retrieving credentials, resetting passwords, and authenticating with recovered secrets are all logged in the CyberArk Vault audit trail and may trigger alerting. Have written authorization and a scope before you touch production.

For each finding this section answers three questions: **under which circumstances is it actually exploitable**, **why it works**, and **how to test/validate it**. CyberArkHound only tells you a misconfiguration *exists* — these steps confirm whether it is *reachable and abusable from your position*.

### Preconditions that gate every CCP finding

The three CCP findings (`CCP_UNRESTRICTED_APP`, `CCP_UNRESTRICTED_RETRIEVAL`, `CCP_DEFAULT_AIMWEBSERVICE`) all depend on the same two things:

1. **Network reachability to the CCP web service.** Credentials are served from `https://<CCP_Server>/AIMWebService/api/Accounts`. The CCP/CP component usually runs on a dedicated server (sometimes co-located with PVWA or behind a load balancer). If you cannot reach that host/port, the finding is not exploitable *from where you are*, regardless of how the AppID is configured. Find it from: the URL applications/scripts use to fetch secrets, CI/CD pipeline config, the `AIMWebService` IIS site, or by probing likely hosts for `/AIMWebService/v1.1/aim.asmx` / `/AIMWebService/api/Accounts`.
2. **The AppID is a safe member with Use/Retrieve on the target safe.** An AppID that authenticates but is a member of nothing returns *"object not found"*, not a password. The `CyberArk_CanRetrieveViaCCP` edges already tell you exactly which safes/accounts each AppID can reach — use them to pick a target.

**The single most useful diagnostic is the CCP error code.** A request that *authenticates* but matches nothing returns something like `APPAP004E Password object matching query ... was not found` — that already proves the AppID is accepted from your position. Authentication/restriction failures look different: `APPAP008E ... is not defined`, `APPAP306E ... not authorized` / address-restriction errors, or `ITATS982E` (machine not allowed). If you get an *authorization/address* error, an unseen restriction (often a network/IP ACL in front of CCP) is blocking you even though the AppID config itself is unrestricted.

### `CCP_UNRESTRICTED_APP` — Unrestricted CCP applications (Critical)

- **What it is:** an AppID with *no* authentication factor configured — no Allowed Machines, no OS user, no path, no hash, no certificate (`isUnrestricted: true`).
- **Why it works:** CCP authenticates the *application*, not a person. The configured factors (machine address, OS user, executable path, binary hash, client certificate) are the application's credential. With **zero** factors, the AppID *string itself* is the only secret — and CyberArkHound prints it as `app.name`. CCP retrieval needs no interactive PVWA login and is **not subject to dual-control approval**.
- **Exploitable when:** you can reach the CCP service (precondition 1) and the AppID can read at least one safe (precondition 2). Note: a network-layer IP allowlist in front of CCP can still gate you even though the *application object* is unrestricted — the `APPAP`/`ITATS` error tells you which.
- **How to test:**
  ```bash
  # 1. Prove the AppID authenticates from your position (expect a password OR "object not found"):
  curl -sk "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=exact&Query=Safe=<safe>"

  # 2. Retrieve a specific credential the app can read (pick the target from a CanRetrieveViaCCP edge):
  curl -sk "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&Safe=<safe>&UserName=<user>&Address=<address>"
  # -> JSON; the plaintext password is in the "Content" field.
  ```
- **Confirm impact:** if the recovered account maps to AD (`CyberArk_SyncsToADUser` / `CyberArk_CanConnect` edges), validate the secret out-of-band (e.g. `kinit`, `evil-winrm`, or an SMB auth) to prove it is live.
- **Remediation:** add at least one strong factor — Allowed Machines *plus* path/hash or a client certificate. Machine/IP alone is the weakest (spoofable / shared CI hosts).

### `CCP_UNRESTRICTED_RETRIEVAL` — Credentials retrievable by unrestricted AppIDs (Critical)

- **What it is:** the "so what" of the finding above — the specific **Application → Account** paths where an unrestricted AppID holds `retrieveAccounts` (not merely `useAccounts`), so CCP will hand back the **plaintext password**. Each count is one reachable credential.
- **Why it's worse than `useAccounts`:** `useAccounts` is intended for PSM-brokered connections; `retrieveAccounts` returns the secret in the `Content` field. The talk's whole point is that this turns "4 GET requests" into domain admin — these edges are exactly those GETs.
- **Exploitable when:** same preconditions, and the edge property `canRetrievePassword: true`.
- **How to test:** for each edge, build an **Exact** query from the account's safe/username/address and confirm the password returns:
  ```bash
  curl -sk "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=exact&Query=Safe=<safe>;UserName=<user>;Address=<address>"
  ```
  Prefer **Exact** over **RegExp** — RegExp sweeps return one match per request and generate the `"Too many password objects"` / `"The Credential Provider has encountered an error"` responses that defenders alert on (see [Tradecraft Reference](ccp-tradecraft.md#tradecraft-reference)).
- **Prioritize:** sort these by what the account *is* — accounts with a `CyberArk_SyncsToADUser` edge to a Domain Admin, or `CyberArk_CanConnect` to a Tier-0 host, are the crown jewels.

### `CCP_DEFAULT_AIMWEBSERVICE` — Default AIMWebService application present (High)

- **What it is:** the out-of-the-box `AIMWebService` AppID exists. It is created with the CCP web service and, in many deployments, ends up a member of a broad set of safes.
- **Why it matters:** the AppID name is **publicly known** — an attacker doesn't have to discover it. If it is also unrestricted (check `isUnrestricted` / the `appIsUnrestricted` edge property) it is the fastest path to "read everything."
- **Exploitable when:** it is a member of target safes *and* not locked down. In a **hardened** install, AIMWebService is restricted to the provider hosts themselves (Allowed Machines = the CP/CCP servers); then it is only usable *from those hosts* — which is exactly what the `CyberArk_CCPAllowedFrom` edges and `machineIsOnlyRestriction` flag tell you. If that flag is true, compromising one of those provider hosts is the route in.
- **How to test:**
  ```bash
  curl -sk "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=AIMWebService&QueryFormat=exact&Query=Safe=<safe>;UserName=<user>"
  ```
  An `APPAP`/`ITATS` address error means it is machine-restricted — pivot to a host listed by `CyberArk_CCPAllowedFrom` and retry from there.
- **Remediation:** scope its safe membership to the minimum, bind it to the provider hosts with strong factors, or remove it if GUI-based application provisioning isn't used.

### `PLATFORM_WILDCARD_ALLOWEDSAFES` — Platforms with wildcard AllowedSafes (`.*`) (High)

- **What it is:** a platform whose `AllowedSafes` regular expression matches **any** safe (`allowedSafesIsWildcard: true`). This is an *enabling* misconfiguration, not a one-GET exploit — it removes the guardrail that ties a platform (and its automation accounts/policies) to specific safes.
- **Why it matters:** `AllowedSafes` is what stops a powerful platform — especially one with a **reconcile** or **logon** account (often a domain admin) — from being associated with accounts in safes it was never meant to touch. With `.*`, that privileged reconcile credential can be brought to bear far more widely, and you can stage accounts onto the platform from any safe you can write to.
- **Exploitable when (any of):**
  - You hold **Add Accounts** on some safe and can create an account that *uses this platform*, then drive its credential-management automation (e.g. trigger a **reconcile**) so the platform's privileged reconcile account acts on your behalf. Inspect the platform's `linkedAccountTypes` and follow `CyberArk_LinkedTo {linkType:"reconcile"}` / `{linkType:"logon"}` edges to find that account and the safe it lives in.
  - You can retrieve/use the platform's reconcile or logon account directly (then it's a normal credential-access path, but the wildcard means it can be wielded against accounts in unexpected safes).
- **Why it's "High" not "Critical":** it requires a second permission (account creation or access to the linked account) to weaponize — it widens blast radius rather than handing over a password by itself.
- **How to test (intrusive — lab / change-controlled only):**
  1. From the graph, identify the platform's reconcile/logon account and its safe.
  2. In a safe where you have **Add Accounts**, create a throwaway account that uses the wildcard platform and is configured to reconcile.
  3. Trigger reconciliation (`POST /API/Accounts/{id}/Reconcile`) and observe — in the account activity — that the platform's privileged reconcile account performed the action. That confirms the privileged account can be reached via this platform from a safe you control.
- **Remediation:** set `AllowedSafes` to an explicit list/regex scoped to the safes the platform is meant to manage.

### `RECONCILE_HIJACK_EXPOSURE` — Reconcile-account hijack paths (High)

- **What it is:** `CyberArk_CanHijackViaReconcile` edges — a principal who holds `addAccounts` or `manageSafe` on a safe (`viaSafe`) whose platform defines a privileged **reconcile** account (the target of the edge). This maps the talk's *"Hijacking accounts under a platform with a Reconcile Account"* technique.
- **Why it works:** the reconcile account is the credential the CPM uses to **reset** an account's password when it falls out of sync — it is typically highly privileged (often a domain admin). If you can create or redirect an account on that platform and point it at a victim, the CPM will use the reconcile account to set the **victim's** password to a value stored in the Vault, which you then retrieve. You never need the reconcile account's own password; you borrow its privileges.
- **Exploitable when:** you can add or modify an account on the reconcile-enabled platform (the `permissions` edge property shows which rights you hold), the platform auto-manages or you can trigger reconciliation (`initiateCPMAccountManagementOperations`), and the reconcile account actually has rights over the victim (follow the reconcile account's `CyberArk_SyncsToADUser` / `CyberArk_CanConnect` edges to gauge reach).
- **How to test (intrusive — lab / change-controlled only):**
  ```bash
  # 1. Create an account on the reconcile-enabled platform, addressed at the victim:
  curl -s -X POST "https://<pvwa>/PasswordVault/API/Accounts" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"safeName":"<viaSafe>","platformId":"<reconcilePlatform>","userName":"<victim>","address":"<victim-host>","secretType":"password"}'

  # 2. Trigger reconciliation (CPM uses the privileged reconcile account):
  curl -s -X POST "https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Reconcile" -H "Authorization: Bearer $TOKEN"

  # 3. Retrieve the victim's now-reset password:
  curl -s -X POST "https://<pvwa>/PasswordVault/API/Accounts/<accountId>/Password/Retrieve" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
  ```
- **Destructive — heed this:** step 2 **resets the victim's password**, which breaks legitimate use of that account and is highly visible (Windows 4724/4738 reset events; CyberArk audit). Only run against a throwaway victim in a lab or under explicit change control.
- **Remediation:** scope `AllowedSafes` on reconcile-enabled platforms, restrict `addAccounts`/`manageSafe` on safes those platforms manage, and require dual control on reconcile operations.

### `PSM_BREAKOUT_EXPOSURE` — PSM-routed accounts without session isolation/recording (Medium)

- **What it is:** accounts brokered by a PSM server (`managedByPSM: true`) whose platform has **session isolation disabled** (`sessionMonitoringEnabled: false`) and/or **recording disabled** (`sessionRecordingEnabled: false`). This is the exposure surface for the talk's *"Platform breakouts to PSM servers"* (HTML5 gateway) vector.
- **Why it matters:** PSM is meant to isolate the user from the target and the credential, and to record the session. When isolation is off, the connection may be a *raw* RDP/SSH (the credential is more exposed and the session is easier to break out of to reach the PSM host); when recording is off, a breakout attempt is far quieter. Compromising the PSM host yields access to **every** credential it brokers.
- **Important scope note:** the breakout itself is a **host-level** technique — escaping the published RDP/HTML5 application to get code execution on the PSM server. CyberArkHound maps **where the exposure is** (which accounts route through PSM, via which server, with what monitoring), not the breakout exploit. Use the [PSM infrastructure edges](edges.md#edge-types-summary) (`CyberArk_ManagedByPSM`, `CyberArk_UsesPSMServer`, `CyberArk_PSMServerHostedOn`) to identify the target PSM host and its underlying AD computer.
- **Exploitable when:** you have `useAccounts` (PSM-connect) on one of these accounts, the connection component is interactive (RDP/SSH/HTML5 — see `CyberArk_HasConnectionComponent`), and the PSM host is reachable/escapable. Prioritize accounts whose PSM host (`CyberArk_PSMServerHostedOn` → Computer) is itself a high-value or weakly-hardened box.
- **How to test:**
  1. From the graph, pick a `managedByPSM` account with monitoring/recording off that you can `useAccounts` on, and note its PSM server (`CyberArk_ManagedByPSM`) and host (`CyberArk_PSMServerHostedOn`).
  2. Initiate the PSM session (`POST /API/Accounts/{id}/PSMConnect`) and attempt standard published-app escape techniques **within engagement scope** to land on the PSM host.
  3. Success = code execution on the PSM server, from which brokered credentials/recordings are reachable.
- **Remediation:** enable *Require privileged session monitoring and isolation* and *Record and save session activity* on the platform (Master Policy), and harden the PSM hosts against published-app breakout.

### `SAFE_NO_CPM` — Safes without CPM management (Medium)

- **What it is:** a safe with no managing CPM (`managingCPM` empty), so its credentials have **no automatic rotation**.
- **Why it matters:** it is a **force-multiplier**, not a standalone exploit. Credentials in these safes are likely static and long-lived, which means: (a) anything you recover now will *keep working*; (b) a secret captured from an old export, backup, ticket, or wiki is probably still valid; (c) for Windows accounts, a captured NTLM hash stays usable for pass-the-hash because the password never changes.
- **Exploitable when:** you already have (or later get) *any* exposure of an account in one of these safes — via a CCP finding above, a `CyberArk_HasAccessTo` path, or an out-of-band leak. The lack of CPM is what makes that exposure durable.
- **How to assess:**
  - Cross-reference which accounts in these safes are reachable: do they have `CyberArk_HasAccessTo` or `CyberArk_CanRetrieveViaCCP` edges? Those are the credentials whose value won't rotate out from under you.
  - Check the account's `lastModifiedTime` / `lastReconciledTime` to confirm staleness (a years-old timestamp is a strong signal).
  ```cypher
  MATCH p=(s:CyberArk_Safe)-[:CyberArk_Contains]->(a:CyberArk_Account)
  WHERE (s.managingCPM IS NULL OR s.managingCPM = "")
  RETURN p ORDER BY a.lastModifiedTime
  ```
- **Remediation:** assign a CPM to the safe and enable periodic change/verification on the accounts.

### `GRANT_WITHOUT_ACCESS` — Principals who can grant themselves access they do not have (Medium)

- **What it is:** a principal with `manageSafe` or `manageSafeMembers` on a safe (`CyberArk_CanGrantAccessTo`) who has no `useAccounts`/`retrieveAccounts` on the accounts in it.
- **Why it matters:** the principal is one permission change away from every credential in the safe, and an access review that only asks "who can use these accounts" does not list them.
- **Exploitable when:** you control the principal (or a member of the group). Add yourself, or raise your own permissions, through the safe-members API, then retrieve.
- **How to assess:** built-in administrative groups (for example Vault Admins) are expected here; look at the others. Changing safe membership is audited, so the escalation is visible to anyone watching the safe's activity.
- **Remediation:** separate safe administration from account use deliberately, keep the list of safe managers short, and alert on safe-member changes.

### `DUAL_CONTROL_BYPASS` — Principals who bypass dual-control approval (Medium)

- **What it is:** accounts in the safe require approval before use, but the principal holds `accessWithoutConfirmation` and gets them unapproved (`bypassesApproval: true` on its `CyberArk_HasAccessTo` edges).
- **Why it matters:** the control that reviewers assume protects these accounts does not apply to these principals.
- **How to assess:** confirm each bypass is intended (break-glass and automation accounts often are) and that the principals are few and closely held. A group here extends the bypass to all its members.
- **Remediation:** remove `accessWithoutConfirmation` where it is not needed.

### `DUAL_CONTROL_NO_APPROVERS` — Dual control required but the safe has no approvers (Medium)

- **What it is:** the account's platform requires dual-control approval, and no current member of its safe holds `requestsAuthorizationLevel1` or `requestsAuthorizationLevel2`.
- **Why it matters:** either nobody can use the account, because requests can never be confirmed, or the control is not applied in practice. Which one depends on the vault's configuration, so check rather than assume.
- **How to assess:** try a request as a member without `accessWithoutConfirmation`. Note that the `requiresApproval` edge property is `false` for these accounts, because CyberArkHound treats approval as enforceable only where approvers exist.
- **Remediation:** add approvers to the safe, or take the platform out of dual control if that was the intent.

### `INACTIVE_USER_WITH_ACCESS` — Disabled or suspended users that still hold access (Medium)

- **What it is:** a user that is disabled or suspended but is still a safe member with access or grant rights.
- **Why it matters:** the permissions are dormant, not gone. Re-enabling the user, or the directory account it is synced from, restores them at once, and such accounts are rarely watched.
- **How to assess:** check whether the user also inherits access through groups (`CyberArk_MemberOf`), which this finding does not count.
- **Remediation:** remove the safe memberships of users that are not coming back.

### `ACCOUNT_NOT_MANAGED` — Accounts with automatic management disabled (Medium)

- **What it is:** an account whose `automaticManagementEnabled` is false, so the CPM does not rotate, verify or reconcile its password. `manualManagementReason` records why, when someone filled it in.
- **Why it matters:** like `SAFE_NO_CPM`, it makes any exposure of the credential durable.
- **How to assess:** check `lastModifiedTime` for how old the password is, and who can reach the account.
- **Remediation:** re-enable automatic management, or document the exception and rotate by hand.

### `UNLISTED_PRINCIPAL_WITH_ACCESS` — Safe members missing from the user and group lists (Low)

- **What it is:** a user or group that holds safe permissions but was not returned by the Users or Groups API, so it exists in the graph only as a placeholder.
- **Why it matters:** its status, group memberships and directory mapping could not be reviewed. Typical causes are principals deleted from the directory but not from the safe, built-in members, and users the collector is not allowed to see.
- **How to assess:** expect noise when the collection was limited (`--limit-users`, `--limit-groups`) or user details failed to load; the run's INCOMPLETE reasons say so.
- **Remediation:** remove memberships of principals that no longer exist, and give the collector visibility of the rest.
