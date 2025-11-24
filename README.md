## CyberArkHound

Export CyberArk PVWA data (users, groups, safes, accounts and permissions) into a BloodHound-compatible OpenGraph JSON file for security analysis and attack path visualization. The refactored implementation separates concerns into modules for client access, graph construction, export serialization, and a clean CLI entrypoint.

### Features
- **Robust API client** with exponential backoff retry logic and optional SSL customization
- **Comprehensive data extraction**: Users, groups, safes, accounts with full property sets
- **Permission-based access modeling**: Direct account access vs privilege escalation paths
- **LDAP/Directory sync tracking**: Identify synced vs local users and groups
- **External AD entity inference**: Automatic detection of relationships to Active Directory
- **Enriched metadata**: Personal details, vault authorizations, safe permissions, account management status
- **Safe permission tracking**: Per-user/group safe access with permission details
- **External edges preserved**: AD sync relationships stored separately for cross-domain analysis
- **Modular architecture**: Clean separation for easier maintenance, testing, and extension
- **Debug logging**: Comprehensive diagnostics for troubleshooting data flow

### CyberArk User Permissions Required
To successfully ingest data from CyberArk PVWA, the API user needs specific vault authorizations:
The user running this tool must have the **Audit Users** vault authorization. This built-in authorization grants:
- Read access to all users and groups in the vault
- Read access to all safes and their members
- Read access to all accounts (without retrieving passwords)
- View safe member permissions

#### Recommended Setup
Create a dedicated service account for BloodHound data collection:

1. **Create Vault User**: `bloodhound-collector` (or similar)
2. **Grant Vault Authorization**: `Audit Users`
3. **Authentication Method**: CyberArk authentication (LDAP/RADIUS also supported)
4. **User Type**: EPVUser (non-LDAP) or Directory User

#### What the Tool Can Access
With `Audit Users` authorization, the tool can:
- ✅ List all safes in the vault
- ✅ List all safe members and their permissions
- ✅ List all accounts in safes (metadata only)
- ✅ List all vault users and groups
- ✅ View user group memberships
- ❌ **Cannot** retrieve or view account passwords
- ❌ **Cannot** modify any vault objects

#### API Endpoints Used
- `POST /API/Auth/CyberArk/Logon` - Authentication
- `GET /API/safes` - List all safes
- `GET /API/Safes/{safeUrlId}/Members` - List safe members and permissions
- `GET /API/Accounts` - List accounts (filtered by safe)
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

### Installation
Create and activate a virtual environment (recommended) then install dependencies:
```pwsh
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Usage
Run the modular CLI (preferred):
```pwsh
python -m cyberarkhound.cli \ 
	--pvwa https://pvwa.example.com \ 
	--username api_user \ 
	--password $Env:CYBERARK_PASSWORD \ 
	--output export.json \ 
	--target-domains corp.example.com lab.example.com
```

Legacy one-file entry point remains available:
```pwsh
python CyberArkHound.py --help
```

### Arguments (excerpt)
- `--pvwa` Base PVWA URL (e.g., https://pvwa.example.com)
- `--username` / `--password` Credentials (consider using env var for password)
- `--output` Destination JSON file for BloodHound import
- `--target-domains` One or more AD domain names used to link accounts to AD users
- `--workers` Concurrency for per-account detail fetch (default 50)
- `--insecure` Disable SSL verification (NOT recommended for production)
- `--ca-bundle` Path to custom CA bundle for SSL verification
- `--auth-timeout` Authentication timeout in seconds (default 360)
- `--req-timeout` Request timeout in seconds (default 360)
- `--limit-*` Testing limits (users, groups, safes) for development/testing
- `--test-safe` Narrow scope to a specific safe search term
- `--quiet` Suppress info/debug logs
- `--debug` Add verbose debug diagnostics and permission analysis
- `--log-level` Set logging level: DEBUG, INFO (default), WARNING, ERROR

**Example with debugging:**
```pwsh
python -m cyberarkhound.cli \
    --pvwa https://pvwa.corp.com \
    --username svc-bloodhound \
    --password $env:CYBERARK_PASSWORD \
    --output cyberark_export.json \
    --target-domains corp.example.com lab.example.com \
    --debug
```

### Edge Types and Permission Interpretation

The tool creates different edge types based on the permissions a user/group has on a safe:

#### CyberArkHasAccessTo (User/Group → Account)
**Direct account access** - User/group can immediately use or retrieve account credentials:
- `useAccounts`: Use accounts via PSM connections without viewing passwords
- `retrieveAccounts`: Retrieve and view account passwords

**Pattern**: When a user has these permissions on a safe, edges are created from the user directly to **each account** in that safe. This clearly shows which accounts the user can access.

**BloodHound Query Examples:**
```cypher
// Find all accounts a user can access
MATCH (u:CyberArkUser {name: "jdoe"})-[:CyberArkHasAccessTo]->(a:CyberArkAccount)
RETURN a.name

// Find all users who can access a specific account
MATCH (u:CyberArkUser)-[:CyberArkHasAccessTo]->(a:CyberArkAccount {name: "prod-db-admin"})
RETURN u.name

// Find LDAP users with direct account access
MATCH (u:CyberArkUser {isLDAPSynced: true})-[:CyberArkHasAccessTo]->(a:CyberArkAccount)
RETURN u.name, a.name
```

#### CyberArkCanGrantAccessTo (User/Group → Safe)
**Privilege escalation** - User/group can modify safe to grant themselves account access:
- `manageSafe`: Update safe properties, recover safe, delete safe
- `manageSafeMembers`: Add/remove safe members and modify their permissions

**Attack path**: A user with `manageSafeMembers` can add themselves with `retrieveAccounts`, then access all accounts in the safe. This edge points to the **safe** itself since the user must first escalate privileges before accessing accounts.

**BloodHound Query Examples:**
```cypher
// Find privilege escalation paths to accounts
MATCH (u:CyberArkUser)-[:CyberArkCanGrantAccessTo]->(s:CyberArkSafe)-[:CyberArkContains]->(a:CyberArkAccount)
RETURN u.name, s.name, a.name

// Find users who can grant themselves access to production safes
MATCH (u:CyberArkUser)-[:CyberArkCanGrantAccessTo]->(s:CyberArkSafe)
WHERE s.safeName CONTAINS "prod"
RETURN u.name, s.safeName
```

#### Other Edge Types
- `CyberArkMemberOf`: User is member of a group
- `CyberArkContains` (Safe → Account): Safe contains an account
- `SyncsToCyberArkUser`: AD User syncs to CyberArk User (external edge)
- `SyncsToCyberArkGroup`: AD Group syncs to CyberArk Group (external edge)
- `SyncsToADUser`: CyberArk Account syncs to AD User (external edge)

**Note**: Permissions like `listAccounts`, `viewAuditLog`, `addAccounts`, `updateAccountContent` do **not** create access edges as they don't allow password retrieval or account usage.

### Node Properties

#### CyberArkUser Properties
- **Identity**: `userId`, `name`, `userType`, `source`, `isLDAPSynced`
- **Status**: `enabled`, `suspended`, `componentUser`
- **Authentication**: `allowedAuthenticationMethods`, `vaultAuthorization`
- **Directory**: `distinguishedName`, `location`, `authorizedInterfaces`
- **Personal Details**: `firstName`, `lastName`, `email`, `businessEmail`, `businessPhone`, `mobilePhone`, `title`, `organization`, `department`, `profession`, `address` (street, city, state, zip, country)
- **Memberships**: `groupsMembership` (list of group names)
- **Permissions**: `safePermissions` (JSON array with safeName, permissions, hasDirectAccess, canGrantAccess)

#### CyberArkGroup Properties
- **Identity**: `groupId`, `name`, `groupType`, `isDirectorySynced`
- **Directory**: `directory`, `distinguishedName`, `location`
- **Metadata**: `description`, `memberCount`
- **Members**: `members` (list of usernames)
- **Permissions**: `safePermissions` (JSON array with safe access details)

#### CyberArkSafe Properties
- **Identity**: `safeName`, `safeUrlId`, `safeNumber`
- **Metadata**: `description`, `location`, `creator`
- **CPM**: `managingCPM`, `olacEnabled`
- **Retention**: `numberOfVersionsRetention`, `numberOfDaysRetention`, `autoPurgeEnabled`
- **Timestamps**: `creationTime`, `lastModificationTime`
- **Settings**: `isExpiredMembershipEnable`

#### CyberArkAccount Properties
- **Identity**: `accountId`, `userName`, `platformId`, `address`
- **Safe**: `safeName`, `safeUrlId`
- **Status**: `status`, `disabled`, `secretType`
- **Management**: `automaticManagementEnabled`, `manualManagementReason`
- **Timestamps**: `createdTime`, `lastModifiedTime`, `lastVerifiedTime`, `lastReconciledTime`, `categoryModificationTime`
- **CPM**: `lastModifiedBy`
- **Extended**: `platformAccountProperties` (JSON), `secretManagement` (JSON)

### Output
The resulting JSON structure follows BloodHound OpenGraph schema:
```json
{
  "graph": {
    "nodes": [
      {
        "id": "causer-jdoe",
        "kinds": ["CyberArkUser", "CyberArkBase"],
        "properties": {
          "name": "jdoe",
          "isLDAPSynced": true,
          "vaultAuthorization": "[\"Audit Users\", \"Safe Managers\"]",
          "safePermissions": "[{\"safeName\":\"Production\",\"permissions\":[\"useAccounts\",\"retrieveAccounts\"],\"hasDirectAccess\":true}]",
          "email": "jdoe@corp.com",
          "department": "IT Security"
        }
      },
      {
        "id": "caaccount-12345",
        "kinds": ["CyberArkAccount", "CyberArkBase"],
        "properties": {
          "name": "prod-db-admin",
          "platformId": "WinServerLocal",
          "address": "prod-sql-01.corp.com",
          "safeName": "Production",
          "automaticManagementEnabled": true
        }
      }
    ],
    "edges": [
      {
        "kind": "CyberArkHasAccessTo",
        "start": "causer-jdoe",
        "end": "caaccount-12345",
        "properties": {
          "matchedPermissionNames": ["useAccounts", "retrieveAccounts"],
          "via": "casafe-Production",
          "viaSafeName": "Production"
        }
      }
    ]
  }
}
```

**External edges** (AD sync relationships) are included in the same structure with `match_by` metadata for cross-domain correlation.
```json
{
	"graph": {
		"nodes": [ { "id": "...", "kinds": ["CyberArkUser"], "properties": {"name": "..."} } ],
		"edges": [ { "kind": "CyberArkHasAccessTo", "start": {"value": "...", "match_by": "id"}, "end": {"value": "...", "match_by": "id"} } ]
	}
}
```
External edges (SyncsToCyberArkUser / Group / ADUser) are included with `match_by` set to `name` where appropriate.

### Data Flow Diagram
High-level relationship visualization between CyberArk entities and inferred external AD objects:

```mermaid
---
config:
 layout: elk
---
flowchart TD
 User["fa:fa-user User"] -. SyncsToCyberArkUser<br>(LDAP) .-> CyberArkUser["fa:fa-user CyberArkUser"]
 Group["fa:fa-user-group Group"] -. SyncsToCyberArkGroup<br>(Directory) .-> CyberArkGroup["fa:fa-user-group CyberArkGroup"]
 CyberArkAccount["fa:fa-user-secret CyberArkAccount"] -. SyncsToADUser<br>(Domain Match) .-> User
 CyberArkUser -- CyberArkMemberOf --> CyberArkGroup
 CyberArkGroup -- CyberArkMemberOf --> CyberArkGroup
 CyberArkUser == CyberArkHasAccessTo<br>(useAccounts/retrieveAccounts) ==> CyberArkAccount
 CyberArkGroup == CyberArkHasAccessTo<br>(useAccounts/retrieveAccounts) ==> CyberArkAccount
 CyberArkUser -. CyberArkCanGrantAccessTo<br>(manageSafe/manageSafeMembers) .-> CyberArkSafe["fa:fa-vault CyberArkSafe"]
 CyberArkGroup -. CyberArkCanGrantAccessTo<br>(manageSafe/manageSafeMembers) .-> CyberArkSafe
 CyberArkSafe -- CyberArkContains --> CyberArkAccount
 style User fill:#17E625,stroke:#0B8A14,stroke-width:2px
 style CyberArkUser fill:#BFD6E3,stroke:#7BA3C0,stroke-width:2px
 style Group fill:#FFED29,stroke:#CCB900,stroke-width:2px
 style CyberArkGroup fill:#C8DCC0,stroke:#8FB888,stroke-width:2px
 style CyberArkAccount fill:#E7C8C8,stroke:#C09999,stroke-width:2px
 style CyberArkSafe fill:#E8D8B3,stroke:#C0AC7F,stroke-width:2px
```

**Legend:**
- **Solid Lines** (→): Internal CyberArk relationships (membership, containment)
- **Thick Lines** (⇒): Direct account access edges
- **Dashed Lines** (⇢): External sync relationships or privilege escalation

### BloodHound Custom Node Definitions
The file `cyberark_model.json` defines custom node types (icons & colors) for BloodHound via the API Explorer `custom-nodes` endpoint:

```json
{
	"custom_types": {
		"CyberArkAccount": {"icon": {"type": "font-awesome", "name": "user-secret", "color": "#E7C8C8"}},
		"CyberArkGroup":   {"icon": {"type": "font-awesome", "name": "user-group",  "color": "#C8DCC0"}},
		"CyberArkSafe":    {"icon": {"type": "font-awesome", "name": "vault",       "color": "#E8D8B3"}},
		"CyberArkUser":    {"icon": {"type": "font-awesome", "name": "user",        "color": "#BFD6E3"}}
	}
}
```

#### Applying Custom Types
Use the BloodHound API (adjust host & auth):
```pwsh
curl -X POST -H "Content-Type: application/json" -d @cyberark_model.json https://bloodhound.example.com/api/custom-nodes
```
Or place/merge into your existing customization workflow before ingesting the exported graph.

After loading, BloodHound will render CyberArk nodes with meaningful icons/colors matching the diagram above.

#### Maintaining
- Extend with additional CyberArk-derived types by adding entries under `custom_types`.
- Keep color palette distinct for rapid visual triage (avoid near-duplicate hex codes).
- Version the file if distributing across teams (e.g., `cyberark_model.v1.json`).

### Logging and Verbosity Control

The tool provides flexible logging control to balance visibility with output volume:

#### Log Levels
Use `--log-level` to control progress reporting frequency:

**WARNING/ERROR** - Minimal output, only critical messages:
```pwsh
python -m cyberarkhound.cli --pvwa ... --log-level WARNING --output export.json --target-domains corp.com
```
- Shows start/end of major phases
- No intermediate progress updates
- Best for automated/scheduled runs

**INFO** (default) - Balanced progress updates:
```pwsh
python -m cyberarkhound.cli --pvwa ... --log-level INFO --output export.json --target-domains corp.com
```
- Progress every 50 users/groups
- Progress every 20 safes
- Progress every 100 accounts/members
- Progress every 100 nodes during export
- Progress every 500 edges during export
- Recommended for interactive runs

**DEBUG** - Detailed progress for troubleshooting:
```pwsh
python -m cyberarkhound.cli --pvwa ... --log-level DEBUG --output export.json --target-domains corp.com
```
- Progress every 10 users/groups
- Progress every 5 safes
- Progress every 25 accounts/members/nodes
- Progress every 100 edges
- Additional diagnostic information
- Best for troubleshooting or understanding processing flow

#### Additional Logging Options
- `--quiet` - Suppress most logging (overrides log-level)
- `--debug` - Enable permission analysis diagnostics
- Environment variable override:
  ```pwsh
  $Env:CYBERARKHOUND_LOG_LEVEL = "INFO"
  python -m cyberarkhound.cli --pvwa ... --output export.json --target-domains corp.com
  ```

#### Example Output (INFO level)
```
[2025-11-24 10:15:23] INFO cyberarkhound: Processing 500 users...
[2025-11-24 10:15:24] INFO cyberarkhound:   Processed 50/500 users (10.0%)
[2025-11-24 10:15:25] INFO cyberarkhound:   Processed 100/500 users (20.0%)
...
[2025-11-24 10:15:30] INFO cyberarkhound:   Processed 500/500 users (100.0%)
[2025-11-24 10:15:30] INFO cyberarkhound: Processing 3000 accounts...
[2025-11-24 10:15:35] INFO cyberarkhound:   Processed 100/3000 accounts (3.3%)
...
[2025-11-24 10:16:45] INFO cyberarkhound: Writing JSON to file: export.json
[2025-11-24 10:16:45] INFO cyberarkhound:   Total nodes: 3750, Total edges: 8500
[2025-11-24 10:16:45] INFO cyberarkhound:   Writing compact JSON format...
[2025-11-24 10:16:48] INFO cyberarkhound: Export complete! File written successfully.
```

#### Performance Tips
- Use `--log-level WARNING` for large environments (10K+ objects) to minimize logging overhead
- Use `--log-level DEBUG` only when investigating specific issues
- Progress updates have minimal performance impact but can fill log files in very large environments
- Compact JSON format is always used (no pretty-printing) for optimal write performance

### Development
Module layout:
```
cyberarkhound/
	client.py      # API interactions
	graph.py       # Graph construction
	exporter.py    # Serialization to BloodHound JSON
	utils.py       # Helpers (logging, property sanitation)
	cli.py         # Argument parsing / orchestration
```

### Extending
Add new edge types or property mappings inside `graph.py`. Keep transformations pure and avoid network calls there. For additional export formats create a new module (e.g. `neo4j_exporter.py`) and reuse the existing OpenGraph object.

### Security Notes
- Prefer supplying credentials via environment variables or a secure secret store.
- Avoid `--insecure` outside of controlled test environments.
- Validate custom CA bundle integrity before use.

### Contributing
1. Fork and create feature branch
2. Add tests or minimal repro script if introducing complex logic
3. Keep changes small and focused; update README where behavior changes
4. Submit PR describing rationale and any edge cases

### Quick Dry Run (no real data)
You can perform a structural dry run by mocking empty collections:
```pwsh
python - <<'PY'
from cyberarkhound.graph import build_opengraph
from cyberarkhound.exporter import export_opengraph_to_bloodhound_json
og, external = build_opengraph([], [], [], [], [], ["example.com"], debug=True)
export_opengraph_to_bloodhound_json(og, external, "dryrun.json", debug=True)
print("dryrun.json written")
PY
```

### Support

Open issues for bugs or enhancement requests. Provide snippet of failing input and Python version.

## Acknowledgments
Thank you to Siemens Healthineers for supporting this research and to my coworkers who have helped with its development.
- Julian Garcia - for cooperating with this research, and for offering valuable perspective for coding practices.