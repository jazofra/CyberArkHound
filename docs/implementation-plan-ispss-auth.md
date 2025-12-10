# Implementation Plan: ISPSS Authentication Support (v2 - LLM Optimized)

**Issue:** #1 - Add support for CyberArk Privilege Cloud Shared Services
**Date:** 2025-12-10
**Branch:** `feature/ispss-auth` (CREATED)

---

## CURRENT STATUS (2025-12-10)

### Completed Tasks:
- [x] **Pre-flight**: Feature branch created, upstream synced
- [x] **A1-A7**: Go implementation COMPLETE and verified
- [x] **B1-B7**: Python implementation COMPLETE and verified
- [x] **C1**: Documentation update COMPLETE

### What Remains:
Nothing - ready to commit and create PR.

---

## Quick Resume Commands

```bash
cd /home/tim/CyberArkHound
git status  # Should be on feature/ispss-auth branch

# Verify Go build works
go build -o /tmp/cyberarkhound-test ./cmd/cyberarkhound
/tmp/cyberarkhound-test --help | grep auth-mode

# Verify Python works
python3 -c "from cyberarkhound.auth import ISPSSAuthenticator; print('OK')"
python3 -m cyberarkhound.cli --help | grep auth-mode
```

---

## Files Modified/Created

| File | Status | Action |
|------|--------|--------|
| `go.mod` | DONE | Added ark-sdk-golang dependency |
| `pkg/client/auth.go` | DONE | NEW FILE - Authenticator interface + implementations |
| `pkg/client/client.go` | DONE | Added isISPSS field, Bearer header, NewClientWithAuthenticator |
| `cmd/cyberarkhound/main.go` | DONE | Added --auth-mode, --identity-url flags |
| `requirements.txt` | DONE | Added ark-sdk-python |
| `cyberarkhound/auth.py` | DONE | NEW FILE - Python authenticators |
| `cyberarkhound/client.py` | DONE | Added authenticator support, Bearer header |
| `cyberarkhound/cli.py` | DONE | Added --auth-mode, --identity-url flags |
| `README.md` | PENDING | Need to add ISPSS documentation |

---

## Task C1: Update README.md (PENDING)

**File:** `README.md`

**Action:** Add this content after existing usage examples (find appropriate location):

```markdown
## Authentication Modes

CyberArkHound supports two authentication modes:

### On-Premise CyberArk PAM (Default)

```bash
# Go
./cyberarkhound --pvwa https://pvwa.example.com \
    --username admin --password secret \
    --output output.json --target-domains DOMAIN.COM

# Python
python3 -m cyberarkhound.cli --pvwa https://pvwa.example.com \
    --username admin --password secret \
    --output output.json --target-domains DOMAIN.COM
```

### CyberArk Privilege Cloud (ISPSS)

For CyberArk Privilege Cloud (Identity Security Platform Shared Services):

```bash
# Go
./cyberarkhound --auth-mode ispss \
    --username "service-user@cyberark.cloud.12345" \
    --password "secret" \
    --output output.json --target-domains DOMAIN.COM

# Python
python3 -m cyberarkhound.cli --auth-mode ispss \
    --username "service-user@cyberark.cloud.12345" \
    --password "secret" \
    --output output.json --target-domains DOMAIN.COM
```

**Notes for ISPSS mode:**
- The `--pvwa` flag is **not required** (PVWA URL is auto-discovered from tenant)
- Use an **Identity Service User** account (not interactive Identity User with MFA)
- The service user must have appropriate permissions in CyberArk (e.g., "Audit Users")
- Username format: `username@cyberark.cloud.XXXXX` where XXXXX is your tenant identifier

#### GovCloud / Custom Identity URL

For government cloud or custom Identity deployments, override the Identity URL:

```bash
./cyberarkhound --auth-mode ispss \
    --username "service-user@cyberark.cloud.12345" \
    --password "secret" \
    --identity-url "https://custom.id.cyberark.cloud" \
    --output output.json --target-domains DOMAIN.COM
```
```

---

## Final Steps After C1

1. **Verify everything works:**
```bash
# Go
go build -o /tmp/cyberarkhound-test ./cmd/cyberarkhound
/tmp/cyberarkhound-test --help | grep -E "auth-mode|identity-url"

# Python
python3 -m cyberarkhound.cli --help | grep -E "auth-mode|identity-url"
```

2. **Commit changes:**
```bash
git add -A
git status
git commit -m "feat: Add ISPSS (Privilege Cloud) authentication support

- Add ark-sdk-golang and ark-sdk-python dependencies
- Create Authenticator interface with CyberArk and ISPSS implementations
- Add --auth-mode flag (cyberark/ispss) to CLI
- Add --identity-url flag for GovCloud/custom deployments
- Auto-discover PVWA URL from tenant subdomain for ISPSS
- Use Bearer token format for ISPSS authentication

Closes #1"
```

3. **Push and create PR:**
```bash
git push -u origin feature/ispss-auth
gh pr create --title "feat: Add ISPSS (Privilege Cloud) authentication support" --body "Closes #1"
```

---

## Key Implementation Details

### Authorization Header Difference
- **On-premise:** `Authorization: {token}`
- **ISPSS:** `Authorization: Bearer {token}`

### PVWA URL Auto-Discovery
Identity endpoint `https://abc123.id.cyberark.cloud` → PVWA `https://abc123.privilegecloud.cyberark.cloud`

### SDK Usage
- **Go:** `authmodels.IdentityServiceUser` with `auth.NewArkISPAuth(false)`
- **Python:** `ArkAuthMethod.IdentityServiceUser` with `ArkISPAuth(cache_authentication=False)`
