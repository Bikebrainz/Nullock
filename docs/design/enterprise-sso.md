# Design: Enterprise SSO

Status: draft / design-only (no code yet). Target: v4.
Companion: [team-workspaces.md](team-workspaces.md) (SSO is how workspace members
authenticate).

## Goal

Let an organization require its operators to sign in through the corporate
identity provider (IdP) before they can reach a Nullock **server** (the workspace
server, or a hosted/shared control server), and map IdP identity + group
membership onto Nullock roles.

## Non-goals

- **Gating the local single-user desktop app.** Local mode stays auth-free and
  offline (its localhost `Origin`/`X-Nullock-UI` guard at
  `control_server.cpp:910-975` is sufficient there). SSO protects the *server*
  surface only.
- Becoming an IdP. We integrate with Okta / Entra ID / Google / Auth0 / Keycloak,
  we don't issue primary credentials.
- SCIM auto-provisioning and enforced-MFA passthrough (later phase).

## Scope boundary (important)

There are two auth surfaces and they stay separate:

| Surface | Auth today | Auth with SSO |
| --- | --- | --- |
| Local desktop app → its own control server | localhost Host whitelist + `Origin`/`X-Nullock-UI` (`control_server.cpp:910-975`) | unchanged |
| Desktop/web client → workspace/hosted server | n/a (doesn't exist yet) | **SSO session (bearer)** |

The localhost guard is kept verbatim for local mode. The server mode adds a
bearer-session check ahead of the existing per-request handling.

## Protocol choice

**OIDC (Authorization Code + PKCE) is primary.** It is JSON/JWT, works with every
major IdP, and PKCE fits a desktop "public client" with no safely-storable
secret. **SAML 2.0 is a phase-3 fallback** for orgs that mandate it; flag the
cost up front — SAML needs XML-DSig validation (an `xmlsec`/libxml2 dependency),
which is heavier than anything Nullock links today.

## Flow (OIDC Authorization Code + PKCE)

```
 desktop/web client            Nullock server                 org IdP
        │  GET /api/... (no session)  │                          │
        │ ◀── 401 + authorize URL ────│                          │
        │  open system browser ───────┼────── /authorize ───────▶│
        │                             │        (PKCE challenge,   │
        │                             │         state, nonce)     │
        │ ◀──────────── redirect to /auth/callback?code ─────────│
        │  (browser hits server)      │── code+verifier ─────────▶│ /token
        │                             │ ◀── id_token + access ────│
        │                             │  validate id_token        │
        │                             │  (iss/aud/exp/nonce,      │
        │                             │   RS256 vs JWKS)          │
        │ ◀── server session token ───│  map groups → role        │
        │  Authorization: Bearer <s>  │                          │
        │  GET /api/... ─────────────▶│  validate session, role  │
```

Key choice: **the server issues its own short-lived session token**, it does not
hand the raw IdP token to the client. This decouples API auth from IdP token
lifetime, lets the session carry the resolved workspace role, and keeps IdP
tokens off the wire after login.

## Token validation — the one real new dependency

Nullock has **no JWT validation library today**, and the existing `jwt_tool`
(`jwt_tool.hpp:23-69`) is an **attack** toolkit (alg:none forgery, HS brute,
RS256→HS256 confusion) — it must **not** be reused to validate real tokens.

ID-token verification is RS256 against the IdP's JWKS. Qt's
`QMessageAuthenticationCode` is HMAC-only, so it can't do RS256. OpenSSL is
already present transitively (the cert authority shells to `openssl` and TLS
goes through `QSslSocket`/OS OpenSSL). **Recommendation: add `libcrypto`
(OpenSSL) as a first-class build dependency and verify RS256 + parse JWKS with
it** (or vendor a thin header-only verifier like `jwt-cpp` that sits on
libcrypto). Cache the JWKS, honor key rotation via the `kid` header.

The server's *own* session token can be a JWT signed with a server key
(HS256/RS256) or an opaque random id backed by a session table — opaque is
simpler to revoke (see below).

## Role mapping

IdP group/claim → Nullock role (`owner`/`editor`/`viewer`, per
[team-workspaces.md](team-workspaces.md)). A per-workspace mapping table
(`group → role`), **default-deny** for unmapped users.

## Session management

- Short-lived access session (e.g. 1h) + refresh (silent re-auth or refresh
  token). Server-side **revocation list** (the reason to consider opaque
  sessions over self-contained JWTs).
- The server's session-signing key / secret lives in server config (env, like
  `nullock-oast`) or an OS keychain.
- The client stores its session token at rest using the **per-OS private-key
  lockdown pattern already in `cert_authority.cpp:35-68`** (POSIX chmod 0600 /
  Windows single-user DACL) — reuse it for the token file, or the OS keychain.

## Security checklist

- PKCE (public client), `state` (CSRF on the callback), `nonce` (ID-token
  replay), **exact** redirect-URI registration, TLS everywhere.
- Validate `iss`, `aud`, `exp`, `nbf`, signature, and `nonce` on the ID token.
- Short sessions, rotate the session-signing key, revocation on logout/role
  change.
- Every login (and failure) writes to the workspace `activity` audit log.

## Deployment / config (env, mirroring nullock-oast)

```
OIDC_ISSUER          https://login.example.com/realms/org
OIDC_CLIENT_ID       nullock-workspace
OIDC_CLIENT_SECRET   (omit for pure PKCE public client)
OIDC_REDIRECT_URI    https://nullock.example.com/auth/callback
OIDC_ROLE_MAP        sec-leads=owner,pentesters=editor,readonly=viewer
SESSION_TTL_SECONDS  3600
```

## Phasing

- **Phase 1 (MVP)** — OIDC Auth Code + PKCE against one IdP (validate against
  Keycloak/Auth0 in dev); server-issued sessions; bearer auth ahead of the
  server's `/api/*` handling; RS256 + JWKS verification via OpenSSL; group→role
  map; login audit.
- **Phase 2** — refresh + revocation; OS-keychain token storage on the client;
  multiple IdP configs.
- **Phase 3** — SAML 2.0 SP (`xmlsec`), SCIM provisioning, MFA-step-up signals.

## Decisions needed (product/security)

1. Which IdP(s) to target first (drives the dev test harness).
2. OIDC-only at launch, or is SAML a hard requirement for the target buyer?
3. Approve adding **OpenSSL/libcrypto as a build dependency** for RS256/JWKS
   (recommended) vs shelling out to the `openssl` exe (already done for certs).
4. Self-host only vs an Anthropic-hosted tier (changes secret management + the
   multi-tenant session model).
