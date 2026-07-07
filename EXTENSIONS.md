# Writing Nullock Extensions

Nullock extensions are small **JavaScript** files that hook the proxy pipeline —
observe every response, rewrite outgoing requests, or emit findings into the
same panel the passive scanner uses. They're the equivalent of Burp's extension
API, but without a paid tier and without shipping a whole JVM: each `.js` is
evaluated in an embedded, sandboxed [`QJSEngine`](https://doc.qt.io/qt-6/qjsengine.html).

- [The sandbox](#the-sandbox)
- [The `nullock` API](#the-nullock-api)
- [Permissions](#permissions)
- [A complete example](#a-complete-example)
- [Installing & reloading](#installing--reloading)
- [The marketplace manifest](#the-marketplace-manifest)

## The sandbox

Every extension runs inside a shared `QJSEngine`. That engine is **pure
ECMAScript**: there is **no filesystem, no network, no `require`, no child
processes, no timers** — only the language plus the `nullock` bridge object
Nullock injects. An extension therefore cannot read your disk or phone home; the
only things it can touch are the requests/responses Nullock hands it and the
capabilities described below.

Handlers run on the engine's own thread; when a proxy worker thread needs a
mutation it is marshalled across safely. Header names/values you return are
validated against RFC 7230 (no CR/LF, token-only names) before they touch the
wire, so a handler can't smuggle a header or split a request by accident.

## The `nullock` API

The injected global is `nullock`:

| Call | Purpose | Needs a permission? |
|------|---------|---------------------|
| `nullock.log(msg)` | Write a line to the extension log. | no |
| `nullock.onResponse(fn)` | Observe (and optionally mutate) responses. | mutation only |
| `nullock.onRequest(fn)` | Rewrite outgoing requests before they're sent. | **yes** |
| `nullock.reportFinding(sev, kind, summary, evidence, url)` | Emit a finding (CWE/OWASP/CVSS-enriched, shows in reports/exports). | no |

**`onResponse(fn)`** — `fn(entry)` is called for every response. `entry` has
`method`, `host`, `port`, `path`, `url`, `scheme`, `status`, `reasonPhrase`,
`responseSize`, `bodyPreview` (up to 64 KiB), and `headers` (an array of
`[name, value]` pairs). Return nothing to just observe. Returning a modified
object *mutates the response the client receives* — but only if your extension
holds the `modify-responses` permission (otherwise the return value is ignored).

**`onRequest(fn)`** — `fn(entry)` is called for every outgoing request; `entry`
has `method`, `host`, `port`, `path`, `headers`, and `bodyText`. Return a
modified object to change what's forwarded upstream (`host`/`port` are
immutable). **This requires the `modify-requests` permission** — without it your
handler is refused at load time and never runs.

**`reportFinding(...)`** — surfaces a finding as if the passive scanner had found
it, so it gets the same enrichment and lands in reports/SARIF/exports.

## Permissions

Rewriting traffic is powerful — a malicious extension could silently strip auth
headers or tamper with page content. So the two mutating capabilities are
**default-deny**: an extension must *declare* them, up front, in a header
comment, or the runtime won't wire them.

Declare permissions with a directive anywhere in your file's header comments:

```js
// nullock:permissions modify-requests
```

Multiple permissions are comma- or space-separated (case-insensitive); the
`@nullock-permissions` spelling also works:

```js
// @nullock-permissions modify-requests, modify-responses
```

| Permission | Grants |
|------------|--------|
| `modify-requests` | registering an `onRequest` handler (rewrite outgoing requests). Aliases: `onRequest`. |
| `modify-responses` | applying a mutated object returned from `onResponse`. Aliases: `onResponse-mutate`, `modify-response`. |

Everything else — `log`, observing in `onResponse`, and `reportFinding` — needs
no declaration. An extension with no directive is **observe-only**: it can watch
traffic and report findings, but cannot change a single byte on the wire.

When an extension is loaded the grant is logged, e.g.
`[ext] loaded my_ext.js (granted: modify-requests)` or `(observe-only)`. A
denied `onRequest` logs a clear hint telling you which directive to add.

> **Migration note.** If you installed the built-in extensions before this
> permission model existed, their copies in your extensions dir predate the
> directive and their request-mutation will now be denied. Refresh them with
> `POST /api/extensions/install-builtins` (or reinstall from the marketplace) to
> pick up the versions that declare their permissions.

## A complete example

An observe-only extension that flags any response echoing a common secret
pattern (no permission needed):

```js
// secret_echo.js -- flag responses that echo an obvious secret.
nullock.onResponse(function (entry) {
    if (/AKIA[0-9A-Z]{16}/.test(entry.bodyPreview)) {
        nullock.reportFinding(
            "high", "aws-key-echoed",
            "Response body contains an AWS access key id",
            entry.url, entry.url);
    }
});
```

A request-mutating extension that adds a debug header (needs the permission):

```js
// debug_header.js
// nullock:permissions modify-requests
nullock.onRequest(function (req) {
    req.headers.push(["X-Debug", "nullock"]);
    return req;
});
```

## Installing & reloading

Extensions live in Nullock's per-user data directory:

- Windows: `%APPDATA%\Nullock\Nullock\extensions\`
- Linux/macOS: `~/.local/share/Nullock/Nullock/extensions/`

Drop a `.js` file there and either restart Nullock or `POST
/api/extensions/reload`. `POST /api/extensions/install-builtins` copies the
extensions shipped with Nullock (`extensions/*.js`) into that directory. The
current extension log and loaded scripts are in `/api/snapshot` under
`bootInfo.extensionsLog` / `bootInfo.loadedScripts`.

## The marketplace manifest

`extensions/marketplace.json` catalogs the shipped extensions. Each entry has
`id`, `name`, `summary`, `version`, `author`, `url`, a `hooks` array (which
`nullock.*` APIs it uses), and an optional `config` schema. The permission the
extension actually enforces is the `// nullock:permissions` directive in the
`.js` itself — the manifest's `hooks` is descriptive metadata for the catalog UI.
