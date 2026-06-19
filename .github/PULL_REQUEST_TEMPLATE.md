<!--
Thanks for contributing! Keep one logical change per PR and explain the WHY.
See CONTRIBUTING.md for build/test instructions and the patterns for adding
a scanner, lab, or extension.
-->

## What & why
<!-- What this changes and the problem it solves. -->

## How it was verified
<!-- Tests run, manual repro, or e2e against a headless instance + mock.
     Paste the relevant ctest / nullock output. -->

## Checklist
- [ ] Builds clean (`cmake --build build --config Release --target NullockApp`)
- [ ] Regression suites pass (`ctest -R "scanner_regression|cve_database|finding_enricher|request_export"`)
- [ ] New finding kinds are mapped in `finding_enricher.cpp` (if any)
- [ ] New active probes are `ScopeGuard`-gated (if any)
- [ ] No literal secrets in fixtures (minted at runtime instead)
- [ ] Docs / `--help` / `CHANGELOG.md` updated (if user-facing)
