# Changelog

Notable changes to CyberArkHound. Releases before this file was started are
described by their [release notes](https://github.com/jazofra/CyberArkHound/releases).

## Unreleased

### Changed — check before upgrading

- **Exit code 2 for incomplete exports.** A run that writes an export flagged
  INCOMPLETE used to exit with 0 and now exits with 2. Scripts that stop on
  any non-zero exit code will stop on a partial export; accept 2 explicitly
  where a partial graph is good enough.
- **Module path.** The Go module is now `github.com/jazofra/CyberArkHound`
  (it was `github.com/siemens-healthineers/cyberarkhound`). Update imports if
  you use the packages as a library.
- **`--auth-method windows`** now answers the NTLM handshake of the logon
  request instead of posting the user name and password in its body.
- **`CyberArk_UsedAccount`** edges gain `retrieveCount`, `connectCount`,
  `cpmCount` and `credentialAccess`. Queries for dormant access should filter
  on `credentialAccess: true` to leave out CPM housekeeping; the query library
  has been updated.

### Added

- Findings: `GRANT_WITHOUT_ACCESS`, `DUAL_CONTROL_BYPASS`,
  `DUAL_CONTROL_NO_APPROVERS`, `INACTIVE_USER_WITH_ACCESS`,
  `ACCOUNT_NOT_MANAGED` and `UNLISTED_PRINCIPAL_WITH_ACCESS` (see
  [docs/findings.md](docs/findings.md)).
- `--fail-on <severity>` exits with code 3 when findings reach a severity.
- `--findings-format` and extension detection: findings reports as SARIF, CSV
  or Markdown as well as JSON.
- `bypassesApproval` on `CyberArk_HasAccessTo` edges and
  `dualControlWithoutApprovers` on accounts.
- RADIUS logons that are answered with a challenge prompt for the response.
- `--save-raw` names ending in `.gz` are written gzip-compressed; `--resume`
  and `--from-raw` read both forms.
- `go install github.com/jazofra/CyberArkHound/cmd/cyberarkhound@latest`.
- An Apache-2.0 `LICENSE`; the project had no licence file before.
- `SECURITY.md`, this changelog, and reference documentation under `docs/`.

### Fixed

- Safes, safe members and accounts were listed only up to the first page
  shorter than the requested page size. A PVWA that caps the page size below
  that ended the listing after one page, without a warning. Listings now
  follow `nextLink`.
- Members and accounts whose safe name was spelled with different letter case
  by different APIs were not joined, which dropped their access edges.
- A PVWA host name with non-ASCII letters produced a node-ID tag containing
  those letters.
- A very large `Retry-After` value overflowed into a negative delay.

### Internal

- The graph builder is split into one pass per kind of object.
- CI runs golangci-lint, enforces a coverage floor and fuzzes the parsers of
  PVWA-supplied text briefly on every change.
