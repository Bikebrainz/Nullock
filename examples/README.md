# Nullock recipes

Real-world scripts that drive Nullock from the shell or Python. All
assume a running Nullock instance, launched with:

```
NullockApp --headless --ndjson
```

and listening on `127.0.0.1:17777` (the default).

## What's in here

| File | What it does |
|---|---|
| `ci-scan-and-sarif.sh` | Proxy a target through Nullock, run the active probe across every captured row, export findings as SARIF, fail the build on any `high` finding. Fit for GitHub Actions / GitLab CI. |
| `headless-portsweep.sh` | Sweep a CIDR with the discovery preset, dump open hosts as nmap XML, print a one-line summary per host. |
| `recon-to-probe.sh` | Recon a domain (DNS + wordlist), probe every found subdomain that responds to HTTP. |
| `tail-events.sh` | Tail the `--ndjson` event stream and pretty-print interesting events. Use as a sidecar while you proxy a target manually. |

Bash scripts use the `nullock` CLI wrapper in `../bin/`. Add it to
`$PATH` or invoke directly.
