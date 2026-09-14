# Maintenance tools

Run these commands from the repository root. The canonical CLI lives in
[`bin/nullock`](../bin/nullock); `scripts/nullock` is a compatibility forwarder.
See [CI](../.github/workflows/ci.yml) for the commands exercised on each platform.

## Documentation and catalogs

| Command | Purpose |
| --- | --- |
| `python scripts/check_web_assets.py` | Check tracked Markdown destinations, website navigation, assets, and browser script integrity without network access. |
| `bash scripts/marketplace_sync.sh --check` | Verify extension hashes, declared permissions, and both marketplace manifests. |
| `python scripts/marketplace_site.py --check` | Check generated marketplace pages. |
| `python scripts/labs_site.py --check` | Check generated lab pages and downloadable project presets. |
| `python scripts/parity_report.py --check` | Check the generated roadmap against its feature register. |
| `python scripts/lab_presets_regression.py` | Validate all lab presets against their source and exact loopback ports. |

Omit `--check` from a catalog generator to regenerate its output. Commit the
source and generated changes together. Markdown destination checks include
inline links, images, and reference definitions; fenced and inline code examples
are ignored. Heading fragments in Markdown are rendered by GitHub and are not
validated here; fragments in committed HTML are checked against actual IDs.

## Application regression checks

Build the application first, then pass its executable as the positional argument
to the Python checks below. For example:

```sh
python scripts/runtime_regression.py build/Src/App/NullockApp
```

On Windows, use `build/Src/App/Release/NullockApp.exe`. macOS bundle paths and
installed-package checks are documented in [packaging](../packaging/README.md).

| Tool | Coverage |
| --- | --- |
| `runtime_regression.py` | Application lifecycle, project isolation, wire fidelity, and installed runtime checks. |
| `annotations_regression.py` | Project-note persistence and synchronization. |
| `intruder_workspace_regression.py` | Intruder workspace persistence and restoration. |
| `outbound_scope_regression.py` | Scope enforcement against owned loopback fixtures. |
| `control_responsiveness_regression.py` | Nonblocking control intake and asynchronous Repeater requests. |
| `workspace_recovery_regression.py` | Project save/load failure recovery. |
| `scanner_sessions_regression.py` | Scanner session state and lifecycle. |
| `probe_smoke.sh` | Active-probe positive and negative fixtures; accepts an optional executable path. |
| `integration_smoke.ps1 -exe <path>` | Windows analysis and reporting integration. |

`annotations_cli_test.py` checks CLI request contracts without a native build.
The CSP browser comparisons run with `node Tests/ui/csp_browser_test.cjs <header_audit_test>`
and `node Tests/ui/csp_policy_browser_test.cjs <header_audit_test>` after installing
`Tests/ui` dependencies and Chromium as shown in CI. They compare the production
analyzer with single, repeated and comma-combined response policies.
`node Tests/ui/header_values_browser_test.cjs <header_audit_test> <xss_reflected_test>`
compares MIME sniffing and referrer-policy decisions with actual browser requests,
including malformed values and repeated fields.
`replay_fuzz_corpus.py <build-dir>` replays committed parser seeds against built
fuzz harnesses. `container_smoke.py <base-url>` checks the container service;
use the fixture setup and environment from CI.

## Historical manual checks

The [legacy archive](legacy/README.md) contains earlier redaction, TLS, and
endpoint checks. They are retained for coverage review, separate from the
maintained scripts above, and are not current CI entry points.

Put new automated regressions beside the related maintained script or in
[`Tests/`](../Tests/). Keep fixture traffic on owned loopback services, accept
executable paths explicitly, and clean up only processes started by the check.
