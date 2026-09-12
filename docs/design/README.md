# Design docs

Implementation designs for larger roadmap features — written before code so the
approach, data model, and dependencies are agreed up front. These are living
drafts, not commitments; each ends with the decisions still owed by
product/security.

| Doc | Roadmap item | Status |
| --- | --- | --- |
| [team-workspaces.md](team-workspaces.md) | v3 — team workspaces | draft, design-only |
| [enterprise-sso.md](enterprise-sso.md) | v4 — enterprise SSO | draft, design-only |

Both are grounded in the current architecture (control server, project store,
the `baseline/diff` identity-key sync primitive, `HistoryIndex`, the
`nullock-oast` deployable-binary pattern) with file:line citations, so they can
be picked up and executed without re-discovering how Nullock works.
