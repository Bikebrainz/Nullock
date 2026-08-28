# Nullock Labs

Intentionally-vulnerable apps for practicing with Nullock. Each lab is
self-contained: one Python file + one walkthrough, runs on `localhost`,
with no dependencies beyond Flask (plus `requests`, `pyjwt`, or
`cryptography` for the handful of labs that need them -- see "Run"
below).

```
labs/
  01-xss-mirror/      # Reflected XSS in a search-echo handler           (5001)
  02-sqli-basic/      # Error-based SQLi via a string-concatenated query (5002)
  03-jwt-weak/        # JWT signed with a short / leaked / `none` alg    (5003)
  04-idor/            # IDOR -- /profile/<id> with no ownership check    (5004)
  05-ssrf/            # SSRF via /fetch?url=... (no host allow-list)     (5005)
  06-graphql/         # GraphQL introspection + over-fetching            (5006)
  07-ssti/            # Jinja2 SSTI -> RCE via __class__.__mro__         (5007)
  08-oauth-state/     # OAuth callback with missing/unverified state     (5008)
  09-race-condition/  # Time-of-check/time-of-use bank transfer race    (5009)
  10-deserialization/ # Pickle untrusted -> RCE                          (5010)
  11-prototype-pollution/  # Deep-merge __class__ poisoning             (5011)
  12-broken-access/   # Admin endpoint without auth check                (5012)
  13-command-injection/    # Shell metachars in a ping diagnostics tool (5013)
  14-path-traversal/  # ../ escapes the download base dir (LFI)          (5014)
  15-open-redirect/   # /go?next= redirects off-origin, unvalidated      (5015)
  16-cors-misconfig/  # Reflected Origin + Allow-Credentials: true       (5016)
  17-nosql-injection/ # password[$ne]= operator auth bypass             (5017)
  18-mass-assignment/ # over-post is_admin/role onto the profile         (5018)
  19-csrf/            # state-changing POST, no token, no SameSite        (5019)
  20-user-enumeration/     # login error reveals which usernames exist   (5020)
  21-session-fixation/     # sid cookie not rotated on login             (5021)
  22-file-upload/     # unrestricted upload -> stored XSS                 (5022)
  23-host-header-poisoning/ # reset link built from Host header          (5023)
  24-clickjacking/    # sensitive page with no frame protections          (5024)
  25-secret-exposure/ # AWS key in app.js + readable /.env                (5025)
  26-blind-sqli/      # boolean-based blind SQLi (no error output)        (5026)
  27-stored-xss/      # persistent XSS in a comment feed                  (5027)
  28-business-logic-price/ # client-controlled price / negative qty      (5028)
  29-verbose-errors/  # stack-trace info disclosure on bad input          (5029)
  30-rate-limit-bypass/    # X-Forwarded-For resets the login limiter     (5030)
  31-directory-listing/    # autoindex leaks file names + serves them     (5031)
  32-csv-injection/   # =formula survives into the CSV export             (5032)
  33-weak-reset-token/     # reset token = md5(username), predictable     (5033)
  34-2fa-bypass/      # dashboard never checks the 2FA flag               (5034)
  35-reset-token-reuse/    # reset token never invalidated (replayable)   (5035)
  36-http-param-pollution/ # check uses first dup param, action uses last (5036)
  37-web-cache-deception/  # dynamic page at a cacheable static-style URL  (5037)
  38-insecure-cookie-flags/ # session cookie w/o Secure/HttpOnly/SameSite (5038)
  39-missing-security-headers/ # no CSP / nosniff / framing protections   (5039)
  40-ssrf-metadata/   # /fetch reaches internal-only + cloud metadata     (5040)
  41-oauth-redirect-uri/    # redirect_uri unvalidated -> auth-code theft  (5041)
  42-credentials-in-url/    # password in query string (logs/history/Referer) (5042)
  43-xxe/             # external entity resolves a local file into the reply (5043)
  44-crlf-injection/  # redirect param splits the Location header (CWE-113)   (5044)
  45-dangerous-http-methods/ # OPTIONS Allow advertises PUT/DELETE/PATCH      (5045)
  46-verb-tampering/  # /admin gated for GET only; POST/HEAD sail through      (5046)
  47-cache-poisoning/ # unkeyed X-Forwarded-Host reflected, cacheable         (5047)
  48-sensitive-file-exposure/ # .env / .git / *.bak served from web root      (5048)
  49-robots-disclosure/    # robots.txt Disallow maps hidden attack surface   (5049)
  50-predictable-session-token/ # sequential session ids (sequencer verdict)  (5050)
  51-jwt-alg-confusion/    # RS256 token forged as HS256 using the pubkey PEM (5051)
  52-ldap-injection/  # filter metachar breaks the query, wildcard bypasses a blocklist (5052)
  53-jwt-kid-injection/    # kid path-traversal points HMAC verify at an empty key file (5053)
  54-xpath-injection/ # concatenated XPath filter -- error leak + and/or-precedence login bypass (5054)
  55-ognl-struts-injection/ # %{ } OGNL expression evaluated server-side (S2-045 class)       (5055)
  56-cswsh-notifications/  # WS upgrade trusts the session cookie, never checks Origin        (5056)
```

Each lab maps to a Nullock active probe (`cmdi`, `lfi`, `openredirect`,
`cors`, `nosqli`, `massassign`, `xxe`, `crlf`, `verbtamper`, `jwt`, ...),
so you learn the bug class *and* how to confirm it with the tool. This
passed the v4 roadmap goal of a 50-lab Web Security Academy clone and
keeps growing -- every lab here is verified end-to-end against its
Nullock detector.

## Why labs?

Every pentest tool that succeeded -- Burp, ZAP, mitmproxy -- has a
companion teaching surface that drove adoption. PortSwigger's Web
Security Academy is most of why Burp owns the market: people learn
*how to find bugs* on those labs and reach for the tool they learned
on at their day job.

The labs here are scaffolds. Real coverage (auth, session, business
logic, IDOR, SSRF, OAuth, GraphQL, cloud) is months of writing. This
is the v0 -- enough to walk a new user through one finding per
category, end-to-end, with Nullock.

## Run

Each lab is its own `app.py` on a fixed port (`50NN` for lab NN, e.g. lab 43
is on `5043`). From the lab dir:

```sh
pip install flask          # + requests / pyjwt / cryptography for the labs that need them -- check the lab's docstring
python app.py
```

Every lab ships a `.nullock-project.json` that pins scope to the lab host, so
you don't have to `nullock scope add` by hand — point Nullock at it (or just
run the steps in `app.py`'s docstring, which set scope for you). The docstring
is the walkthrough: the vulnerability, the exact `nullock` commands to confirm
it, and the upstream fix.

## Add a lab

PRs welcome. Keep them under 100 lines of Python (Flask + `requests` only).
Each lab is:

1. `app.py` -- runs on a fixed port (`50NN`), with a **module docstring that
   IS the walkthrough**: the vulnerability, the step-by-step `nullock`
   commands to confirm it, and the one-line fix you'd PR upstream.
2. `.nullock-project.json` -- a project preset pinning scope to the lab host
   (`inScope: ["http://localhost:50NN/*", ...]`), so opening the lab is
   pre-scoped. Every lab ships one.

Each lab should map to a Nullock probe (`xxe`, `crlf`, `verbtamper`,
`sequencer`, ...) so the learner confirms the bug with the tool.
