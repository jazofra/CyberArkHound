## CyberArkHound

Export CyberArk PVWA data (users, groups, safes, accounts, platforms and permissions) into a BloodHound-compatible OpenGraph JSON file for security analysis and attack path visualization.

### Quick Start

**Windows:**
```pwsh
# Download or build the binary
go build -o cyberarkhound.exe ./cmd/cyberarkhound

# Run the tool (the password is read from CYBERARK_PASSWORD, or prompted for)
.\cyberarkhound.exe `
    --pvwa https://pvwa.example.com `
    --username svc-bloodhound `
    --output cyberark_export.json `
    --target-domains corp.example.com
```

**Linux/macOS:**
```bash
# Build the binary
go build -o cyberarkhound ./cmd/cyberarkhound

# Run the tool (the password is read from CYBERARK_PASSWORD, or prompted for)
./cyberarkhound \
    --pvwa https://pvwa.example.com \
    --username svc-bloodhound \
    --output cyberark_export.json \
    --target-domains corp.example.com
```

The resulting `cyberark_export.json` file can be directly imported into BloodHound. Use a `.zip` output name (e.g. `--output cyberark_export.zip`) to get a compressed archive that BloodHound also accepts.

**Password handling.** The password (or OAuth `client_secret`) is taken from, in order: `--password`, the `CYBERARK_PASSWORD` environment variable, or an interactive prompt that does not echo. Avoid `--password`: command-line arguments are visible to other local users in the process list, and CyberArkHound logs a warning when it is used.

#### Privilege Cloud (SaaS / ISPSS)

CyberArkHound also supports **CyberArk Privilege Cloud**, the SaaS-based offering on the Identity Security Platform Shared Services (ISPSS). The data model and the PasswordVault REST API are the same as self-hosted PVWA — only **authentication** differs: Privilege Cloud authenticates through **CyberArk Identity**.

With `--auth-method identity`, CyberArkHound authenticates in two stages:
1. **OAuth2 `client_credentials`** — tried first, for [OAuth confidential client service users](#service-user-setup-for-privilege-cloud) (recommended). `--username` and the password are the `client_id`/`client_secret`.
2. **Username/password fallback** — if the `client_credentials` grant is rejected, CyberArkHound falls back to the interactive CyberArk Identity flow (`StartAuthentication` → `AdvanceAuthentication`) and stores the returned platform bearer token. `--username` and the password are the regular Identity username and password.

If the account requires **multi-factor authentication (MFA)** or uses **federated / SAML sign-in**, the username/password fallback cannot complete non-interactively and CyberArkHound returns a clear error — use an OAuth confidential client service user (excluded from MFA) instead.

```bash
./cyberarkhound \
    --auth-method identity \
    --pvwa https://<subdomain>.privilegecloud.cyberark.cloud \
    --identity-url https://<tenant>.id.cyberark.cloud \
    --username <oauth-service-user> \
    --output cyberark_export.json \
    --target-domains corp.example.com
```

Notes:
- `--pvwa` is the **Privilege Cloud** URL (`https://<subdomain>.privilegecloud.cyberark.cloud`). CyberArkHound appends the same `/PasswordVault/API/...` paths used for self-hosted.
- `--identity-url` is the **CyberArk Identity tenant** URL used to obtain the OAuth2 token (`https://<tenant>.id.cyberark.cloud`). The Identity tenant ID is usually **not** the same as the portal subdomain — find it under Identity Administration or in the `oauth2/platformtoken` endpoint your tenant uses.
- `--username` / the password (from `CYBERARK_PASSWORD`, the prompt, or `--password`) are the **OAuth `client_id` / `client_secret`** of a dedicated [OAuth confidential client service user](#service-user-setup-for-privilege-cloud) created in CyberArk Identity (not an interactive portal user).
- The obtained `access_token` is a short-lived bearer token; CyberArkHound automatically re-authenticates when it expires (HTTP 401), reusing the same single-flight refresh logic as self-hosted.

The required vault authorizations (`Audit Users` plus `List`/`View Safe Members` on the safes) are identical to self-hosted — assign them to the service user in Privilege Cloud.

### Features
- **High Performance**: Go implementation with concurrent processing and efficient memory usage
- **Robust API client** with exponential backoff retry logic and optional SSL customization
- **Comprehensive data extraction**: Users, groups, safes, accounts with full property sets
- **Permission-based access modeling**: Direct account access vs privilege escalation paths
- **LDAP/Directory sync tracking**: Identify synced vs local users and groups
- **External AD entity inference**: Automatic detection of relationships to Active Directory
- **Account activity tracking**: Optional CyberArk_UsedAccount edges showing actual usage patterns
- **Linked account chain analysis**: Optional CyberArk_LinkedTo edges mapping logon/reconcile/additional account dependencies, queryable with Cypher to find each linked account's blast radius
- **Safe creator and CPM tracking**: CyberArk_Created and CyberArk_ManagedBy edges showing who created and manages each safe
- **Platform-based grouping**: Optional CyberArk_Platform nodes and CyberArk_UsesPlatform edges for shared attack surface analysis
- **PSM infrastructure mapping**: Optional CyberArk_PSMServer and CyberArk_ConnectionComponent nodes with edges showing which PSM servers and connection protocols (RDP, SSH, etc.) each platform and account uses; CyberArk_PSMServerHostedOn external edges link PSM servers to their AD Computer objects
- **CCP / AIMWebService attack-surface mapping**: Optional CyberArk_Application nodes (AppIDs) with CyberArk_CanRetrieveViaCCP edges showing which credentials each Central Credential Provider application can pull via the AIMWebService REST API. Applications are flagged when they have **no authentication restrictions** (`isUnrestricted`) or are the **default AIMWebService AppID** (`isDefaultCCPApp`), surfacing the "shortest path to privileged accounts" tradecraft documented by [Marat Nigmatullin (FalconForce)](docs/ccp-tradecraft.md#tradecraft-reference) at SO-CON 2026
- **Reconcile-account hijack mapping**: CyberArk_CanHijackViaReconcile edges (principal → privileged reconcile account) show who can coerce the CPM into resetting a target's password via a platform's reconcile account — the second attack vector from [Nigmatullin's SO-CON 2026 talk](docs/ccp-tradecraft.md#tradecraft-reference)
- **Dual control awareness**: Per-account `requiresApproval` derived from platform Master Policy settings (with approver-presence fallback); CyberArk_CanApprove edges identify who can authorize dual-controlled access
- **Master Policy exception detection**: Flags on platform nodes identify deviations from Master Policy defaults for audit and compliance
- **Resilient platform data**: Automatic fallback to `/API/Platforms/Targets` when `/API/Platforms/` is unavailable, preserving all security-relevant properties
- **Enriched metadata**: Personal details, vault authorizations, safe permissions, account management status
- **Safe permission tracking**: Per-user/group safe access with permission details
- **External edges preserved**: AD sync relationships stored separately for cross-domain analysis
- **Security findings summary**: End-of-run report of the highest-value misconfigurations (unrestricted CCP AppIDs, default AIMWebService, wildcard `AllowedSafes`, reconcile-account hijack, dual-control bypass, self-grantable access, disabled users with access, unmanaged accounts, safes without CPM) computed from collected data — no extra API calls; `--findings-output` also writes them, with the affected objects, as JSON, SARIF, CSV or Markdown, and `--fail-on` turns them into an exit code for scheduled jobs
- **Built-in safe members**: Predefined members such as Master, Vault Admins and Auditors are collected (the Safe members API omits them by default)
- **Membership-aware access**: Expired safe memberships produce no access edges; group membership is taken from both each user's details and each group's member list
- **Honest partial exports**: Every lookup that fails (a safe's members, an account's details, a group's member list, ...) is listed in an end-of-run INCOMPLETE report instead of being silently dropped
- **Interruptible**: Ctrl+C stops the collection, logs off, and still exports what was gathered (exit code 130); a second Ctrl+C aborts immediately
- **Resumable collections**: with `--save-raw`, progress is saved every minute and whenever the run stops; `--resume` continues an interrupted or failed collection without fetching finished work again, retries what failed, and produces the same export as an uninterrupted run
- **Offline rebuilds**: `--save-raw` keeps the raw collected data; `--from-raw` rebuilds the graph from it without contacting PVWA
- **Safe output files**: Exports are written atomically with owner-only (0600) permissions; a `.zip` output name produces a compressed archive
- **Deterministic output**: Nodes, edges and permission lists are emitted in a stable, sorted order so exports diff cleanly across runs
- **Debug logging**: Comprehensive diagnostics for troubleshooting data flow

### Documentation

The reference material lives in [`docs/`](docs/):

| Document | Contents |
|----------|----------|
| [Edge types](docs/edges.md) | What each relationship in the graph means, how it is derived from CyberArk permissions, and which properties it carries. |
| [CCP / AIMWebService tradecraft](docs/ccp-tradecraft.md) | How Central Credential Provider applications become attack paths, and the research this mapping is based on. |
| [Cypher query library](docs/queries.md) | Ready-made BloodHound queries for every edge type and finding. |
| [Security findings](docs/findings.md) | The misconfigurations CyberArkHound reports at the end of a run, and how to validate and fix each one. |
| [Output format](docs/output.md) | The exported file, node IDs and node properties, and how the data flows from PVWA to BloodHound. |
| [BloodHound extension](docs/bloodhound-extension.md) | Icons, the OpenGraph extension schema, Entity Panel content and edge traversability. |
| [Logging](docs/logging.md) | Log levels, progress output and performance tips. |

### CyberArk User Permissions Required
To successfully ingest data from CyberArk PVWA, the API user needs specific vault authorizations, the user running this tool must have the **Audit Users** vault authorization which provides read access to all users and groups in the vault.
The users requires 'list' and 'View Safe members' permissions on all safes within CyberArk, either directly or through group membership which will allow the user to view all accounts and safes within CyberArk.

Alternativly the user can be a member of local CyberArk vault group 'Auditors', this will grant the user read only access to all safes, accounts and groups. However the permission to view the session (PSM) recordings which is not advisable

#### Recommended Setup
Create a dedicated service account for BloodHound data collection:

1. **Create Vault User**: `bloodhound-collector` (or similar)
2. **Grant Vault Authorization**: `Audit Users`
3. **Authentication Method**: CyberArk authentication (LDAP, RADIUS and Windows are also supported; see `--auth-method`)
4. **User Type**: EPVUser (non-LDAP) or Directory User
5. **Safe Permissions**: The user needs to be a member of all the safes in the environment or a member of a group that is a member to all the safes in CyberArk. Permissions required are 'list' and 'View Safe Members'
6. **Store this account within CyberArk**: to ensure it is rotated as per CyberArk policies
7. **Retrieve the credential using CCP/CP**: if CCP/CP is used within the environment, use this to retreive the credetial as and when required

#### Service User Setup for Privilege Cloud
For **Privilege Cloud (SaaS / ISPSS)**, the collector authenticates through CyberArk Identity with OAuth2 instead of a PVWA password logon. Create a dedicated OAuth service user:

1. **Create an OAuth service user** in **Identity Administration** (a dedicated, non-interactive user for API/automation).
2. **Enable "Is OAuth confidential client"** in the user's Status checklist — this turns the username/password into an OAuth `client_id` / `client_secret`.
3. **Exclude it from MFA policies** (service users cannot satisfy interactive MFA) and from the User Portal.
4. **Grant the same vault access** as self-hosted: `Audit Users` plus `List` / `View Safe Members` on all safes (directly or via a group).
5. **Run CyberArkHound with `--auth-method identity`**, passing the `client_id` as `--username`, the `client_secret` as the password (via `CYBERARK_PASSWORD` or the prompt), and the Identity tenant URL as `--identity-url`.

> A regular (non-OAuth) CyberArk Identity user also works: CyberArkHound automatically falls back to the username/password `StartAuthentication` → `AdvanceAuthentication` flow when the `client_credentials` grant is rejected. That user must **not** be subject to MFA or federated/SAML sign-in, since those require interactive completion. The OAuth confidential client approach is still recommended because it is purpose-built for non-interactive automation.

#### What the Tool Can view
With `Audit Users` authorization, the tool can:
- ✅ List all vault users and groups
- ✅ View user group memberships

With 'list' and 'View Safe Members' on each safe, the tool can:
- ✅ List all accounts in safes (no credentials)
- ✅ List all safes in the vault
- ✅ List all safe members and their permissions

#### What the Tool can not do:
- ❌ **Cannot** retrieve or view account passwords
- ❌ **Cannot** modify any vault objects
- ❌ **Cannot** modify platform application settings

#### API Endpoints Used
- `POST /API/Auth/{CyberArk,LDAP,radius,Windows}/Logon` - Authentication (self-hosted PVWA; method selected by `--auth-method`)
- `POST /oauth2/platformtoken` on the CyberArk Identity tenant - Authentication (Privilege Cloud / ISPSS, `--auth-method identity`; OAuth2 `client_credentials`, tried first)
- `POST /Security/StartAuthentication` + `POST /Security/AdvanceAuthentication` on the CyberArk Identity tenant - Username/password fallback when `client_credentials` is rejected (`--auth-method identity`; not usable with MFA/SAML accounts)
- `GET /API/safes` - List all safes
- `GET /API/Safes/{safeUrlId}/Members?filter=includePredefinedUsers eq true` - List safe members and permissions, including built-in members (the safe is addressed by PVWA's `safeUrlId`, falling back to the URL-escaped safe name when it is absent) (the filter is dropped automatically, and the gap reported, if PVWA rejects it; disable with `--include-predefined-members=false`)
- `GET /API/Accounts` - List accounts (filtered by safe)
- `GET /API/Accounts/{accountId}` - Get account details, including linked accounts: logon, reconcile, and platform-defined additional accounts (used when `--include-linked-accounts` is set; no extra request)
- `GET /API/Accounts/{accountId}/Activities` - Get account activity logs (optional, requires `--include-activity`)
- `GET /API/Platforms/` - List all platforms with full configuration (optional, requires `--include-platforms`)
- `GET /API/Platforms/Targets` - List target platforms with exception flags (optional, requires `--include-platforms`; also used as fallback when `/API/Platforms/` fails)
- `GET /API/Platforms/Targets/{id}/PrivilegedSessionManagement` - Get per-platform PSM connectors (optional, requires `--include-platforms`)
- `GET /API/PSM/Servers/` - List all PSM servers (optional, requires `--include-psm`)
- `GET /API/PSM/Connectors/` - List all connection components (optional, requires `--include-psm`)
- `GET /WebServices/PIMServices.svc/Applications/` - List CCP/AIMWebService applications (AppIDs) (optional, requires `--include-applications`)
- `GET /WebServices/PIMServices.svc/Applications/{AppID}/Authentications/` - Get per-application authentication restrictions: allowed machines, OS user, path, hash, certificate (optional, requires `--include-applications`)
- `GET /API/Users` - List all users
- `GET /API/UserGroups` - List all groups
- `GET /API/UserGroups/{groupId}` - Get group details with members
- `POST /API/Auth/Logoff` - Session cleanup

#### Security Considerations
- The `Audit Users` authorization is read-only and cannot modify vault data
- API calls do not retrieve password values
- Use a dedicated service account with long/complex password
- Rotate credentials periodically
- Monitor API usage via PVWA audit logs
- Consider IP restrictions for the service account
- Adding the user to the 'Auditors' groups is easy to provide required perms but grants too much access
- Supply the password through `CYBERARK_PASSWORD` or the interactive prompt rather than `--password`, which other local users can see in the process list
- Treat the export, `--save-raw` and `--findings-output` files as sensitive: they map every privileged account and who can reach it. CyberArkHound creates them readable by the owner only (0600); keep them that way when copying them around
- The session token is never written to the logs, even at debug level

#### TLS troubleshooting
CyberArkHound uses Go's current TLS defaults, which reject some legacy server configurations. If connecting to an older PVWA fails during the TLS handshake (errors containing `tls:` or `x509:`), find out which legacy option the server needs and re-enable only that one, for a single run, with the `GODEBUG` environment variable:

| Setting | Re-enables |
|---------|------------|
| `tlsrsakex=1` | RSA key-exchange cipher suites (no forward secrecy) |
| `tls3des=1` | 3DES cipher suites |
| `tlssha1=1` | SHA-1 signatures in TLS 1.2 handshakes |
| `x509negativeserial=1` | Certificates with a negative serial number |
| `tlsmlkem=0,tlssecpmlkem=0` | Leaves out post-quantum key shares, for middleboxes that reject large TLS ClientHello messages |

For example: `GODEBUG=tlsrsakex=1 ./cyberarkhound ...`. These weaken the connection, so fixing the server configuration is the better long-term answer. For a certificate issued by an internal CA, pass it with `--ca-bundle` instead of using `--insecure`.

### Installation

**Requirements:**
- Go 1.26 or later (older Go installations download the required toolchain automatically)
- Git (for cloning the repository)

**Build from source:**
```pwsh
# Clone the repository
git clone https://github.com/jazofra/CyberArkHound
cd CyberArkHound

# Build the binary
go build -o cyberarkhound.exe ./cmd/cyberarkhound

# Or install directly to $GOPATH/bin
go install ./cmd/cyberarkhound
```

**Install with Go, without cloning:**
```bash
go install github.com/jazofra/CyberArkHound/cmd/cyberarkhound@latest
```

**Pre-built binaries:**
Download pre-compiled binaries from the [Releases](https://github.com/jazofra/CyberArkHound/releases) page. Each release is built by the `Release` workflow when a `v*` tag is pushed, for Linux, macOS and Windows (amd64 and arm64), with the latest stable Go. Before running a downloaded binary, check it:

```bash
# The checksum must match the release's SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS

# The binary must have been built by this repository's release workflow
gh attestation verify cyberarkhound_v1.2.3_linux_amd64 --repo jazofra/CyberArkHound
```

`cyberarkhound --version` prints the version a binary was built from.

### Usage

The password is read from the `CYBERARK_PASSWORD` environment variable (or prompted for) in all examples below.

**Basic usage:**
```pwsh
.\cyberarkhound.exe `
    --pvwa https://pvwa.example.com `
    --username api_user `
    --output export.json `
    --target-domains corp.example.com,lab.example.com
```

**With activity tracking:**
```pwsh
.\cyberarkhound.exe `
    --pvwa https://pvwa.corp.com `
    --username svc-bloodhound `
    --output cyberark_export.json `
    --target-domains corp.example.com,lab.example.com `
    --include-activity `
    --activity-days 30 `
    --workers 100
```

**With debugging:**
```pwsh
.\cyberarkhound.exe `
    --pvwa https://pvwa.corp.com `
    --username svc-bloodhound `
    --output cyberark_export.json `
    --target-domains corp.example.com `
    --log-level debug
```

**Keep the raw data, write findings, and rebuild later without PVWA:**
```bash
# Collect once, keeping the raw data and a machine-readable findings report
./cyberarkhound --pvwa https://pvwa.example.com --username svc-bloodhound \
    --output cyberark_export.zip --target-domains corp.example.com \
    --save-raw cyberark_raw.json --findings-output cyberark_findings.json

# Rebuild the graph (e.g. with other target domains, or after upgrading CyberArkHound)
./cyberarkhound --from-raw cyberark_raw.json \
    --output cyberark_export.json --target-domains corp.example.com,lab.example.com
```

**Resume a long collection that was interrupted or failed:**
```bash
# Start with --save-raw: progress is saved every minute and when the run stops
./cyberarkhound --pvwa https://pvwa.example.com --username svc-bloodhound \
    --output cyberark_export.json --target-domains corp.example.com \
    --save-raw cyberark_raw.json

# ...the run is interrupted, crashes, or ends with some safes failing...

# Continue where it stopped (the PVWA URL is taken from the file)
./cyberarkhound --resume cyberark_raw.json --username svc-bloodhound \
    --output cyberark_export.json --target-domains corp.example.com
```

A resumed collection skips the stages (users, groups, safes, platforms, PSM, applications) and the per-safe and per-account work an earlier run finished, and retries everything that failed — so resuming a finished collection that reported INCOMPLETE data retries just the failed parts. It keeps the original run's collection options (`--limit-*`, `--test-safe`, `--activity-*`, `--include-predefined-members`); other flags, such as `--include-*`, `--workers` and `--target-domains`, can differ. The result is the export an uninterrupted collection would have produced, except that data fetched by different runs reflects the vault at different times.

**Performance tips for large environments:**
- Increase `--workers` to 100-200 for faster parallel processing
- Use `--log-level WARNING` to reduce logging overhead
- Workers are a fixed pool: only `--workers` goroutines run, however many accounts there are
- Re-authentication is single-flighted: when multiple workers receive HTTP 401 simultaneously, only one re-authenticates while the others wait and reuse the refreshed token — avoiding thundering-herd token churn
- HTTP 429 (rate limited) responses honour the server's `Retry-After` header and back off exponentially otherwise, up to `--max-rate-limit-retries` times per request
- Use a `.zip` output name to keep very large exports small
- For a sense of scale: a synthetic vault with 5,000 safes and 100,000 accounts (about one million edges) builds and exports from a raw file in about 16 seconds, peaking at about 1.4 GB of memory, with a 380 MB JSON export. Each progress save during a `--save-raw` collection of that size rewrites a roughly 90 MB file in about 2 seconds, once a minute. `go test -run '^$' -bench . ./pkg/graph ./pkg/exporter` measures build and export speed

**Interrupting a collection:** the first Ctrl+C (or SIGTERM) stops the collection, logs off the PVWA session, and builds and exports whatever was collected so far, flagged as INCOMPLETE. With `--save-raw`, the progress is saved too, so the collection can be continued with `--resume`. A second Ctrl+C aborts immediately.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | The export was written and covers everything the collection asked for |
| `1` | Error: nothing usable was exported, or an output file could not be written |
| `2` | The export was written but is flagged INCOMPLETE (some safes, accounts or lookups failed, e.g. with `--continue-on-error`). Continue it with `--resume` |
| `3` | The export was written and there are findings at or above `--fail-on` |
| `130` | Interrupted (Ctrl+C or SIGTERM); what was collected so far was exported |

When several apply, the first of 1, 130, 3, 2 wins. A script that only checks for a non-zero exit code now also stops on an incomplete export; accept code 2 explicitly if a partial graph is good enough.

### Command-Line Arguments

**Required:**
- `--pvwa` Base PVWA URL (self-hosted, e.g. https://pvwa.example.com) or Privilege Cloud URL (e.g. https://<subdomain>.privilegecloud.cyberark.cloud). Not needed with `--from-raw` or `--resume`
- `--username` API username (or OAuth `client_id` when `--auth-method identity`). Not needed with `--from-raw`
- `--output` Destination file for BloodHound import. A `.zip` extension writes the JSON inside a zip archive
- `--target-domains` One or more AD domain names (comma-separated) used to link accounts to AD users. Surrounding spaces and trailing dots are ignored

**Password:** read from, in order, `--password`, the `CYBERARK_PASSWORD` environment variable, or an interactive no-echo prompt. It is the OAuth `client_secret` when `--auth-method identity`. Prefer the environment variable or prompt: `--password` is visible to other local users in the process list.

**Authentication:**
- `--auth-method` Authentication method: `cyberark` (default), `ldap`, `radius`, `windows` for self-hosted PVWA, or `identity` for Privilege Cloud / ISPSS (SaaS) OAuth2
  - `radius`: if the RADIUS server answers the password with a challenge (typically a one-time code), CyberArkHound asks for the response on the terminal and sends it. Without a terminal such a logon fails, and a re-authentication in the middle of a long collection asks again, so prefer an account without a challenge for unattended runs
  - `windows`: integrated Windows authentication. The credentials answer the NTLM (or Negotiate carrying NTLM) handshake of the logon request and are never sent in its body; give the user as `DOMAIN\user` or `user@domain`. Kerberos-only servers are not supported. Windows authentication must be enabled for the PVWA in IIS
- `--identity-url` CyberArk Identity tenant URL for `--auth-method identity` (e.g. https://<tenant>.id.cyberark.cloud) — **required** for Privilege Cloud

**Optional:**
- `--workers` Concurrency for parallel operations (default: 50, recommended: 100-200 for large environments)
- `--insecure` Disable SSL verification (NOT recommended for production)
- `--ca-bundle` PEM file of CA certificates to trust in addition to the system roots (e.g. an internal CA that issued the PVWA certificate). An unreadable file or one without certificates stops the run before any request is sent
- `--auth-timeout` Authentication timeout as a duration, e.g. `2m` (default: 6m)
- `--request-timeout` Request timeout as a duration, e.g. `10m` (default: 6m)
- `--quiet` Show only warnings and errors
- `--debug` Enable debug logging with detailed diagnostics (same as `--log-level debug`)
- `--log-level` Set logging level: DEBUG, INFO (default), WARNING, ERROR (case-insensitive; unknown values are rejected)
- `--user-extended-details-timeout` Timeout for optional `Users?ExtendedDetails=true` before falling back to the basic user list (default: 1m)
- `--safe-page-limit` Safes page size for pagination (default: 100; lower can help slow or error-prone PVWA)
- `--max-reauth-attempts` Max re-authentication attempts on HTTP 401 before giving up (default: 5)
- `--max-rate-limit-retries` Max HTTP 429 retries per request before giving up (default: 10; 0 retries indefinitely)
- `--continue-on-error` Export the data collected so far when safe enumeration fails partway through (default: true; the export is flagged INCOMPLETE)
- `--include-predefined-members` Collect built-in safe members such as Master, Vault Admins and Auditors (default: true)
- `--pvwa-tag` Tag that namespaces node IDs (1–32 letters, digits, `-` or `_`). Defaults to 4 characters derived from the PVWA host name; set a distinct tag per vault when importing several into one BloodHound (see [Output](docs/output.md#output))

When the bulk `GET /API/Users?ExtendedDetails=true` endpoint times out, CyberArkHound falls back to `GET /API/Users` and enriches each user individually through the user details endpoint. This preserves extended user fields while avoiding a single large PVWA response as a hard dependency. The existing `--workers` value controls this per-user enrichment concurrency.

**Activity Tracking:**
- `--include-activity` Include account activity data (creates CyberArk_UsedAccount edges)
- `--activity-days` Number of days to look back for activity (default: 3)
- `--activity-limit` Max activities per account to fetch from API (default: 100)

**Linked Accounts & Platforms:**
- `--include-linked-accounts` Include linked account data (creates CyberArk_LinkedTo edges for logon/reconcile/additional account chains)
- `--include-platforms` Include platform data (creates CyberArk_Platform nodes and CyberArk_UsesPlatform edges)
- `--include-psm` Include PSM server and connection component data (creates CyberArk_PSMServer and CyberArk_ConnectionComponent nodes with linking edges)
- `--include-applications` Include CCP/AIMWebService application (AppID) data (creates CyberArk_Application nodes and CyberArk_CanRetrieveViaCCP edges). Requires the collector to be able to list Applications (typically the `Manage Users` vault authorization or membership in the relevant application safes)

With `--from-raw`, the `--include-*` flags filter what is built from the raw data.

**Additional outputs and offline rebuilds:**
- `--findings-output` Also write the [security findings](docs/findings.md#security-findings), with the objects behind each one, to this file
- `--findings-format` Format of that file: `json`, `sarif`, `csv` or `markdown`. The default, `auto`, goes by the file extension (`.sarif`, `.csv`, `.md`) and otherwise writes JSON
- `--fail-on` Exit with code 3 when there are findings of this severity or higher: `critical`, `high`, `medium` or `low`. Useful to fail a scheduled job or pipeline on new exposure
- `--save-raw` Also save the raw collected data (no credentials) to this JSON file. A name ending in `.gz` is written gzip-compressed, which is typically a small fraction of the size; `--resume` and `--from-raw` read either form. While collecting, progress is saved to it every minute and whenever the run stops, so the collection can be resumed. On very large vaults, where one save takes many seconds, saves are spaced further apart so they never take more than about a tenth of the run
- `--resume` Continue an interrupted or failed collection from its `--save-raw` file. Finished work is not fetched again and failed work is retried; progress keeps being saved to the same file (or to `--save-raw`, if given). `--pvwa` defaults to the file's PVWA URL; the password and authentication flags are needed as for any collection
- `--from-raw` Build the graph from a `--save-raw` file instead of contacting PVWA. Node IDs keep the original PVWA tag. A file from an unfinished collection builds a graph flagged INCOMPLETE

**Testing/Development:**
- `--limit-users` Limit number of users to process (0 = no limit)
- `--limit-groups` Limit number of groups to process (0 = no limit)
- `--limit-safes` Limit number of safes to process (0 = no limit)
- `--test-safe` Process only safes matching search term

### Development
Module layout:
```
cmd/cyberarkhound/
    main.go            # CLI flags, password and signal handling
    run.go             # One collection or offline rebuild, exit codes
    collect.go         # Resumable collection stages and checkpoints
    report.go          # Findings report formats (JSON, SARIF, CSV, Markdown)
cmd/gen-schema/
    main.go            # Regenerates extension/schema.json from the Go info maps
pkg/
    client/
        client.go      # CyberArk PVWA API client
    models/
        models.go      # Data structures for API responses
    graph/
        builder.go     # OpenGraph construction, one pass per kind of object
        findings.go    # Security findings computed from the built graph
        kinds.go       # Canonical node/edge kind lists, edge traversability (+ go:generate)
        edge_info.go   # EdgeInfoMap — per-edge-kind Entity Panel docs
        node_info.go   # NodeInfoMap — per-node-kind Entity Panel docs
        entity_info.go # EdgeInfo/NodeInfo -> schema "info" accordion sections
        explore_links.go # NodeExploreSections — Explore-link panel sections (templates)
        schema.go      # schema.json round-trip + info injection
        pvwa_tag.go    # PVWA URL tagging algorithm
        utils.go       # Graph utilities, permission maps
    exporter/
        exporter.go    # BloodHound JSON export
    snapshot/
        snapshot.go    # Raw collection files (--save-raw, --resume, --from-raw)
docs/                  # Reference documentation (edges, queries, findings, ...)
extension/
    schema.json        # OpenGraph extension definition (generated info blocks)
```

### Extending
Add new edge types or property mappings inside `pkg/graph/builder.go`: each kind of object has its own pass (`addUsers`, `addSafeMembers`, ...) on the `builder` struct, which holds the indexes the passes share. Keep transformations pure and avoid network calls there. For additional export formats create a new package (e.g. `pkg/neo4j/exporter.go`) and reuse the existing OpenGraph object.

When you add a node or edge kind, register it in `pkg/graph/kinds.go` (edge kinds also need an `EdgeTraversability` entry), add its Entity Panel documentation to `NodeInfoMap`/`EdgeInfoMap`, and run `go generate ./...` to refresh `extension/schema.json`. The drift-guard tests in `pkg/graph/schema_test.go` enforce that the canonical kinds, the model/schema files, and the info maps all stay in sync.

### Security Notes
- Prefer supplying credentials via environment variables or a secure secret store.
- Avoid `--insecure` outside of controlled test environments.
- Validate custom CA bundle integrity before use.

### Contributing
1. Fork and create feature branch
2. Add tests or minimal repro script if introducing complex logic
3. Keep changes small and focused; update README where behavior changes
4. Submit PR describing rationale and any edge cases

### License

CyberArkHound is licensed under the [Apache License 2.0](LICENSE): you may use, modify and redistribute it, including commercially, as long as you keep the licence and copyright notices. Contributions are accepted under the same licence.

### Support

Open issues for bugs or enhancement requests.

## Acknowledgments
Thank you to Siemens Healthineers for supporting this research and to my coworkers who have helped with its development.

- Julian Garcia - for cooperating with this research, and for offering valuable perspective for coding practices.
- Marat Nigmatullin (FalconForce) - for the CCP / AIMWebService and `AllowedSafes=.*` tradecraft ([SO-CON 2026](docs/ccp-tradecraft.md#tradecraft-reference)) that this release maps, and for referencing CyberArkHound in his talk.
