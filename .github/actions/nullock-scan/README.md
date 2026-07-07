# Nullock Security Gate (GitHub Action)

Run the Nullock headless deep-audit against a URL and **fail the job** when a
finding at or above a severity threshold is present — a CI security gate that
Burp only ships in its Enterprise tier.

Under the hood it runs `NullockApp --scan <url> --fail-on <sev>`, which exits
`0` (clean) / `1` (finding at-or-above the threshold) / `2` (bad URL). The
nonzero exit fails the step and the job.

## Inputs

| Input     | Required | Default        | Description |
|-----------|----------|----------------|-------------|
| `url`     | yes      | —              | Target URL, e.g. `https://staging.example.com/` |
| `fail-on` | no       | `high`         | Threshold: `critical`\|`high`\|`medium`\|`low`\|`info`\|`none` (`none` never fails) |
| `ndjson`  | no       | `false`        | Emit one NDJSON result line instead of a human summary |
| `binary`  | no       | `NullockApp`   | Path to a built `NullockApp` binary |

The action assumes a `NullockApp` binary is available (on `PATH` or via the
`binary` input). Point it at a build step, a downloaded release binary, or a
container. See the example workflow below.

## Usage

```yaml
- uses: actions/checkout@v4

# ... build or fetch NullockApp so it's available at build/Src/App/NullockApp ...

- name: Security gate
  uses: ./.github/actions/nullock-scan
  with:
    url: https://staging.example.com/
    fail-on: high
    binary: build/Src/App/NullockApp
```

A complete build-then-gate pipeline lives in
[`../../workflows/nullock-scan-example.yml`](../../workflows/nullock-scan-example.yml).

## Notes

- The scan is a single-target active audit (parameter mining, verb tampering,
  CORS, IDOR, open redirect, cache poisoning, host-header, …). For a full
  engagement, drive the control API (`/api/*`) instead.
- Only scan hosts you are authorized to test.
