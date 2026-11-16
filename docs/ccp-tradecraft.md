# CCP / AIMWebService tradecraft

How Central Credential Provider applications become attack paths, and the research this mapping is based on.

[← Back to the README](../README.md)

## Central Credential Provider (CCP / AIMWebService) Tradecraft

> **Tradecraft credit:** This mapping implements the attack surface presented by **Marat Nigmatullin** (`@_mnigma_`, FalconForce) in **"4 GET requests = 3 Domain admins: CyberArk magic you didn't know about"** at **SO-CON 2026**. See the [Tradecraft Reference](#tradecraft-reference) section for links.

The **Central Credential Provider (CCP)** is an optional CyberArk PAM module that lets applications and services retrieve credentials from the Vault at runtime through a REST API (the **AIMWebService**), instead of hardcoding secrets in config files or scripts. The endpoint is:

```
https://<CCP_Server>/AIMWebService/api/Accounts?<parameters>
```

A single request returns **at most one** matching account. Requests are authenticated by an **Application (AppID)** rather than an interactive PVWA user, and — critically — **are not subject to dual-control approval**.

### Why this matters for attack paths
- An AppID is just an identity object that is a **member of one or more safes** with `retrieveAccounts`/`useAccounts`. If you can reach the CCP endpoint and present a valid AppID, you can pull every credential that AppID is permitted to read — often in **one GET request**.
- The application's only protections are **authentication restrictions**: Allowed Machines (IP/host), OS user, executable path, binary hash, or client certificate. **An AppID with none of these is effectively unauthenticated.** CyberArkHound flags these as `isUnrestricted` / `appIsUnrestricted`.
- The **default `AIMWebService` AppID** that ships with CCP most likely has access to **all safes**. CyberArkHound flags it as `isDefaultCCPApp`.
- **CI/CD runners** (GitLab, Azure DevOps, Bitbucket) that hold an AppID are a common foothold for reaching the CCP endpoint.

### The CCP request parameters
- **AppID** — the application identity making the request.
- **Query** — a flexible filter combining `Safe`, `Object`, `UserName`, `Address`, `Platform`, etc.
- **QueryFormat** — `Exact` (default) or `RegExp`. With `RegExp`, the `Query` value is treated as a regular expression, enabling **vault enumeration one match at a time**.

### Example CCP requests (for authorized testing)
```bash
# Exact retrieval of a single known account:
curl -s "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&Safe=<safe>&UserName=<user>&Address=<host>"

# RegExp filter on username:
curl -s "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=adm"

# RegExp filter on username AND address:
curl -s "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=adm;address=server2"

# Vault enumeration with character classes:
curl -s "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=<AppID>&QueryFormat=regexp&Query=username=som[a-z]username[0-9];Address=hostname[a-z].local"

# The DEFAULT AppID usually reads every safe:
curl -s "https://<CCP_Server>/AIMWebService/api/Accounts?AppID=AIMWebService&QueryFormat=regexp&Query=username=domainadmin;Address=domain1.local"
```
The JSON response includes the plaintext password in the `Content` field plus account metadata.

### Detection (defender's view)
Per the talk, CCP brute force / over-broad RegExp sweeps are detectable from the **response message content**: replies containing `"Too many password objects"` or `"The Credential Provider has encountered an error"` indicate that a query matched more than one object (RegExp returns at most one match per request) — a strong signal of enumeration. CCP usage can also be collected centrally (`GET /AIMWebService` provider logs and CCP usage reports), and retrievals appear in the Vault audit trail under the application identity.

### Related platform misconfiguration: `AllowedSafes=.*`
The same talk highlights platforms whose **`AllowedSafes`** is set to `.*` (match any safe). A platform with a wildcard `AllowedSafes` lets its **reconcile / logon** accounts be attached to unexpected safes, broadening the blast radius of a platform-level compromise. CyberArkHound flags these platforms with `allowedSafesIsWildcard: true` so they can be audited and restricted.

_Queries: [CCP / AIMWebService attack surface](queries.md#ccp--aimwebservice-attack-surface-cyberark_canretrieveviaccp)._

## Tradecraft Reference

The CCP / AIMWebService attack-surface mapping (`CyberArk_Application` nodes, `CyberArk_CanRetrieveViaCCP` edges, the `isUnrestricted` / `isDefaultCCPApp` risk flags, and the platform `allowedSafesIsWildcard` flag) implements the tradecraft presented by:

**Marat Nigmatullin** (`@_mnigma_`, FalconForce) — *"4 GET requests = 3 Domain admins: CyberArk magic you didn't know about"*, **SO-CON 2026**.

- Slides (PDF): [SpecterOps/presentations — SO-CON 2026](https://github.com/SpecterOps/presentations/tree/main/SO-CON%202026)
- Talk recording: <https://www.youtube.com/watch?v=AsKCTlSA15M>
- Author: <https://falconforce.nl> · `marat@falconforce.nl` · [@_mnigma_](https://x.com/_mnigma_)

**Coverage of the talk's three attack vectors:**

| Talk vector | How CyberArkHound maps it |
|-------------|---------------------------|
| **CCP / AIMWebService API abuse** | `CyberArk_Application` nodes + `CyberArk_CanRetrieveViaCCP` / `CyberArk_CCPAllowedFrom` edges; `isUnrestricted` / `isDefaultCCPApp` flags; `CCP_UNRESTRICTED_APP`, `CCP_UNRESTRICTED_RETRIEVAL`, `CCP_DEFAULT_AIMWEBSERVICE` findings |
| **Reconcile-account hijack (CPM)** | `CyberArk_CanHijackViaReconcile` edges (principal → privileged reconcile account); `CyberArk_LinkedTo {linkType:"reconcile"}`; platform `allowedSafesIsWildcard` flag; `RECONCILE_HIJACK_EXPOSURE`, `PLATFORM_WILDCARD_ALLOWEDSAFES` findings |
| **PSM platform breakout (HTML5 gateway)** | PSM infrastructure edges (`CyberArk_ManagedByPSM`, `CyberArk_UsesPSMServer`, `CyberArk_HasConnectionComponent`, `CyberArk_PSMServerHostedOn`); account `managedByPSM` / `sessionMonitoringEnabled` / `sessionRecordingEnabled` posture; `PSM_BREAKOUT_EXPOSURE` finding. *Exposure mapping only — the host-level breakout exploit is out of scope for a graph collector.* |

The talk itself credits Lee Chagolla-Christensen (@SpecterOps) and the YouTube channels @NetSec and @cbyrad, and references CyberArkHound as a complementary tool. Full credit for the CCP/AIMWebService, reconcile-account hijack, PSM-breakout, and `AllowedSafes=.*` tradecraft mapped here belongs to Marat Nigmatullin.

Relevant CyberArk documentation:
- [Call the CCP Web Service using REST](https://docs.cyberark.com/credential-providers/latest/en/content/ccp/calling-the-web-service-using-rest.htm)
- [Central Credential Provider (CCP)](https://docs.cyberark.com/credential-providers/latest/en/content/ccp/the-central%20-credential-provider.htm)
- [Collect CCP usage](https://docs.cyberark.com/credential-providers/latest/en/content/ccp/api-ccp-usage.htm)
