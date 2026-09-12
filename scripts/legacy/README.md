# Historical manual checks

These scripts preserve earlier manual verification work. They are not CI entry
points and have not been ported to the current build paths or fixture lifecycle.
Use the [maintained regression commands](../README.md#application-regression-checks)
for current development.

| Script | Original purpose |
| --- | --- |
| [redteam_r4_verify.ps1](redteam_r4_verify.ps1) | NDJSON query-string redaction and explicit opt-in. |
| [redteam_r5_verify.ps1](redteam_r5_verify.ps1) | Rejection of a self-signed upstream TLS certificate. |
| [redteam_r4_r5_verify.ps1](redteam_r4_r5_verify.ps1) | Early combined redaction and TLS verification. |
| [validate_v3.ps1](validate_v3.ps1) | Early endpoint smoke checks using PowerShell listener jobs. |

The files are retained unchanged for coverage review. They contain a hard-coded
developer executable path; some use external fixtures, fixed ports, or broad
process/job cleanup. Do not use them as unattended checks. Before replacing or
removing one, map its assertions to maintained tests so coverage is preserved.

Add new regression checks to the maintained scripts or `Tests/`, not this archive.
