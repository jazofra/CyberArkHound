# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use GitHub's private vulnerability reporting for this repository: open the
**Security** tab and choose **Report a vulnerability**
(<https://github.com/jazofra/CyberArkHound/security/advisories/new>).

Include what you can of:

- the CyberArkHound version (`cyberarkhound --version`) and how it was installed;
- what an attacker needs (network position, a crafted PVWA response, local access, ...);
- steps or input that reproduce the problem;
- what the impact is.

Do not attach real collection output, raw collection files or findings
reports. They describe a vault in detail; reduce the problem to synthetic data.

## Supported versions

Fixes are made on `main` and shipped in the next release. Only the latest
release is supported.

## What counts

CyberArkHound reads a vault's configuration with the credentials it is given
and writes files describing it. Problems of interest include:

- credentials or session tokens written to logs or output files;
- output, raw or report files created with permissions wider than the owner;
- TLS verification that is weaker than the flags given ask for;
- a malicious or compromised PVWA causing code execution, writes outside the
  given output paths, or requests to hosts other than the ones configured;
- a release binary that does not match its published provenance.

The attack techniques that CyberArkHound maps (CCP AppID abuse, reconcile
account hijack and the others described in `docs/`) are properties of a
CyberArk deployment, not vulnerabilities in this tool. Report those to the
owner of the vault, or to CyberArk if you believe the product is at fault.

## Handling the tool's output

The export, the `--save-raw` file and the findings report are a map of who can
reach which privileged credential. They contain no passwords, but treat them
as sensitive: keep them on encrypted storage, share them only with the people
doing the analysis, and delete them when it is done.
