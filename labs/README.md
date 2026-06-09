# Nullock Labs

Intentionally-vulnerable apps for practicing with Nullock. Each lab is
self-contained: one Python file + one walkthrough, runs on `localhost`,
no external dependencies beyond Flask + requests.

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
```

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

Each lab has its own `app.py`. From the lab dir:

```sh
pip install flask
python app.py
# in another shell -- with Nullock running on 8080:
HTTP_PROXY=http://127.0.0.1:8080 curl http://localhost:5000/
```

## Add a lab

PRs welcome. Keep them under 100 lines of Python. Each lab needs:

1. `app.py` -- runs on `localhost:5000` (or another fixed port noted
   in its README).
2. `README.md` with: vulnerability description, expected exploit,
   step-by-step Nullock walkthrough (which tab, which click, what to
   expect), and the one-line fix you'd PR upstream.
3. (Optional) a `.nullock-project.json` -- pre-set scope to the lab
   host so the user doesn't have to configure scope manually.
