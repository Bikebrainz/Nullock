# Design: Team Workspaces

Status: **Phase 1 (MVP) shipped** — `nullock-workspace` (findings push/pull
sync over SQLite + a shared bearer key); see [DEPLOY_WORKSPACE.md](../DEPLOY_WORKSPACE.md).
Phases 2-3 below are still design-only. Target: v3.
Companion: [enterprise-sso.md](enterprise-sso.md) (the per-user-auth upgrade).

## Goal

Let several operators collaborate on one engagement — shared scope, findings,
triage state, and (optionally) history — with sync between their desktop apps,
**without breaking Nullock's self-host-first, no-telemetry stance**. A team runs
its own workspace server; nothing leaves their infrastructure.

## Non-goals (for the first releases)

- Replacing local single-user mode. The desktop app stays fully usable offline,
  auth-free, against a local project. Workspaces are an opt-in *connect* mode.
- Real-time collaborative editing / CRDTs. Sync is delta-based and eventually
  consistent, not live co-editing.
- Streaming live proxy traffic between operators. History sharing (phase 2) is a
  snapshot/append model, not a live tap.

## Why this is mostly an assembly job

Three primitives already exist and do 80% of the work:

- **A stable finding identity key.** `baseline/save|diff` keys findings on
  `kind + 0x1F + host + 0x1F + url + 0x1F + summary` (U+001F separator) — see
  `control_server.cpp:3429-3432`. That key is exactly what a multi-writer sync
  set needs for upsert/dedup.
- **A delta computation.** `GET /api/baseline/diff`
  (`control_server.cpp:3519-3562`) already computes NEW/FIXED finding sets
  between two snapshots. A workspace is the same diff, generalized from
  "me vs my baseline" to "me vs the shared set."
- **A monotonic change cursor.** `/api/snapshot?since=<seq>` returns 304 when
  `m_seq` is unchanged (`control_server.cpp:1736-1747`). The same since-cursor
  pattern drives workspace pull.

The Finding model to sync is `passive_scanner.hpp:21-38` (severity, kind,
summary, evidence, host, url + CWE/OWASP/CVSS/compliance/fix enrichment).

## Architecture

```
 ┌─────────────┐   HTTPS + bearer    ┌──────────────────────────┐
 │ desktop app │ ──── push/pull ───▶ │  nullock-workspace server │
 │ (operator A)│ ◀─── deltas ─────── │   (headless, container)   │
 └─────────────┘                     │   SQLite (WAL) | Postgres │
 ┌─────────────┐                     │   engagements / findings  │
 │ operator B  │ ◀──────────────────▶│   activity (append-only)  │
 └─────────────┘                     └──────────────────────────┘
```

The **workspace server** is a new headless binary in the `Src/Tools` mold we
just used for `nullock-oast`: env-configured, container-deployable, reuses the
control server's HTTP layer but in a *server* posture (bearer auth instead of
the localhost Origin/`X-Nullock-UI` guard — see Security). It stores shared
engagements centrally; desktop clients sync against it.

Storage: SQLite (WAL) for small teams — same engine/posture as `HistoryIndex`
(`history_index.cpp:36`). A Postgres adapter is the scale path (phase 3); keep
the data-access layer behind an interface so the engine is swappable.

## Data model (server)

```sql
workspaces (id, name, created_by, created_at)
members    (workspace_id, user_id, role)          -- role: owner|editor|viewer
engagements(id, workspace_id, name, scope_json, created_at, updated_seq)

findings   (engagement_id, identity_key,          -- PK (engagement_id, identity_key)
            severity, kind, summary, evidence, host, url,
            enrichment_json,                       -- CWE/OWASP/CVSS/compliance/fix
            status,                                -- open|triaged|false-positive|fixed
            assignee, first_seen, last_seen,
            content_hash, updated_seq, author)

activity   (id, engagement_id, identity_key NULL,  -- append-only audit + comments
            user_id, ts, type, payload_json)       -- comment|status|scope|member|finding
```

`identity_key` is computed exactly as today (`kind + 0x1F + host + 0x1F + url +
0x1F + summary`), so a client's local findings map onto the shared set with zero
translation.
`updated_seq` is a per-engagement monotonic counter (the server's `m_seq`
analog) that drives incremental pull.

## Sync protocol (poll-based first)

```
POST /api/ws/{engagement}/push
  { sinceSeq, findings:[ {identityKey, ...fields, contentHash, updatedAt} ],
    activity:[ {type, identityKey?, payload, ts} ] }
  → { newSeq, accepted, conflicts:[identityKey...] }

GET  /api/ws/{engagement}/pull?since=<seq>
  → { seq, findings:[changed since seq], activity:[since seq], members, scope }
```

Conflict policy (deliberately simple, because findings are mostly additive):

- **Findings**: upsert by `identity_key`. Scalar fields (severity, enrichment)
  are last-write-wins by `updatedAt`; `content_hash` lets the server skip
  no-op writes. `first_seen` never moves back; `last_seen` only forward.
- **Triage state** (status, assignee) and **comments** are recorded as
  append-only `activity` rows, so two operators triaging the same finding never
  destroy each other's input — the latest status wins for display, full history
  is in the log.
- **Scope / members** edits are activity-logged owner/editor operations.

Clients poll `pull` on the existing snapshot cadence. The desktop "push my
findings / pull teammates'" action is the generalized `baseline/diff` flow.

## Roles

`owner` (manage members + settings + delete), `editor` (push findings/activity,
edit scope), `viewer` (pull only). Enforced **server-side per endpoint** — never
trust the client. Roles are assigned per workspace; SSO group→role mapping is in
[enterprise-sso.md](enterprise-sso.md).

## Security

- Every server endpoint is authenticated (bearer session from SSO) **and**
  authorized by role. The localhost `Origin`/`X-Nullock-UI` guard
  (`control_server.cpp:910-975`) is the *local-mode* control; the server mode
  swaps in bearer auth (it is reachable off-localhost by design).
- TLS in front (reverse proxy, exactly like `DEPLOY_OAST.md`).
- The `activity` table **is** the audit trail (who changed what, when).
- No telemetry; the server is the team's own. Findings can contain sensitive
  target data, so history sharing is opt-in per engagement (phase 2) and the
  deploy doc must stress disk encryption + access control on the server box.

## Phasing

- **Phase 0** — lock the engagement/finding/activity schema + identity-key sync
  semantics; write the API spec (this doc → OpenAPI).
- **Phase 1 (MVP)** — `nullock-workspace` headless server (SQLite); push/pull
  findings + scope; role-based bearer auth; a desktop *connect → push → pull*
  flow that reuses the `baseline/diff` machinery. Poll-based.
- **Phase 2** — shared history (opt-in, reuse `HistoryIndex` schema + an
  `engagement_id`/`user_id` column); comments + assignment UI; activity feed.
- **Phase 3** — real-time push (adds a `QWebSocketServer` — none exists today;
  `qtwebsockets` is currently only a frame parser in the proxy); Postgres
  adapter; SSO group→role automation.

## Decisions needed from the team (product)

1. SQLite-only (simplest self-host) vs Postgres option — affects effort.
2. How much history to share by default (privacy + storage vs. usefulness).
3. Self-host only, or also an Anthropic-hosted SaaS tier? (Changes the security
   and multi-tenancy model substantially.)
4. Where the free/paid line sits (this is the first clearly "team/paid" feature).
