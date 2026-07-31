#!/usr/bin/env python3
"""Generate the static marketplace site under docs/marketplace/ from the catalog.

WHY A GENERATOR. The marketplace pages render data from extensions/marketplace.json,
which is exactly the kind of untrusted-shaped content that made the old hand-written
page a stored-XSS sink (it interpolated catalog fields into innerHTML). Generating the
pages here means every value is HTML-escaped ONCE, at build time, by code that cannot
be fooled by a hostile catalog entry -- there is no runtime string-to-HTML path for an
attacker to reach. The index page's search/sort is the only client-side JS, and it
renders through createElement/textContent over a catalog embedded as inert JSON, never
as markup.

Run:
    python scripts/marketplace_site.py          # regenerate the pages
    python scripts/marketplace_site.py --check   # exit 1 if the committed pages are stale

CI runs --check so a catalog or extension edit that is not regenerated fails the build,
the same contract scripts/marketplace_sync.sh already enforces for the manifest hashes.
"""

import html
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "extensions", "marketplace.json")
EXT_DIR = os.path.join(ROOT, "extensions")
OUT_DIR = os.path.join(ROOT, "docs", "marketplace")
E = html.escape  # escape text for element content / attribute values (quote=True)

# One trusted download origin, mirrored from MarketplaceLogic::trustedHosts().
TRUSTED_HOST = "raw.githubusercontent.com"

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


# --------------------------------------------------------------------------- data

def load_catalog():
    with io.open(CATALOG, encoding="utf-8") as f:
        doc = json.load(f)
    exts = doc.get("extensions", [])
    # Deterministic order for stable diffs; the page re-sorts client-side.
    exts.sort(key=lambda e: e.get("id", ""))
    return doc, exts


def fmt_date(iso):
    if not iso:
        return ""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", iso)
    if not m:
        return iso
    y, mo = m.group(1), int(m.group(2))
    return "%s %s" % (MONTHS[mo - 1] if 1 <= mo <= 12 else mo, y)


def read_source(ext_id):
    path = os.path.join(EXT_DIR, ext_id + ".js")
    if not os.path.exists(path):
        return None
    with io.open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


# ----------------------------------------------------------------- syntax highlight

_KW = set((
    "var let const function return if else for while do break continue new try "
    "catch finally throw typeof instanceof in of this null true false undefined "
    "void switch case default delete yield await async class extends super import "
    "export from as").split())

# token kind -> css class (defined in nullock.css under .src-*)
_COL = {"com": "src-com", "str": "src-str", "regex": "src-regex", "num": "src-num",
        "kw": "src-kw", "func": "src-func", "id": "src-id", "punc": "src-punc"}


def _tokenize(src):
    """Port of the mockup tokenizer. Returns a flat list of (kind, text|None)
    where kind 'nl' marks a line break. Purely lexical, good enough for display."""
    out = []
    i, n = 0, len(src)
    prev = None

    def regex_ctx():
        if prev is None:
            return True
        last = prev[-1:]
        if re.match(r"[\w$)\]]", last) and prev not in _KW:
            return False
        return True

    while i < n:
        c = src[i]
        if c == "\n":
            out.append(("nl", None)); i += 1; continue
        if c in " \t":
            j = i
            while j < n and src[j] in " \t":
                j += 1
            out.append(("ws", src[i:j])); i = j; continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i + 2
            while j < n and src[j] != "\n":
                j += 1
            out.append(("com", src[i:j])); i = j; continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = i + 2
            while j < n and not (src[j] == "*" and j + 1 < n and src[j + 1] == "/"):
                j += 1
            j = min(n, j + 2)
            out.append(("com", src[i:j])); i = j; continue
        if c in "\"'`":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2; continue
                if src[j] == c:
                    j += 1; break
                j += 1
            v = src[i:j]; out.append(("str", v)); prev = v; i = j; continue
        if c == "/" and regex_ctx():
            j = i + 1; in_class = False; ok = False
            while j < n:
                d = src[j]
                if d == "\\":
                    j += 2; continue
                if d == "\n":
                    break
                if d == "[":
                    in_class = True
                elif d == "]":
                    in_class = False
                elif d == "/" and not in_class:
                    j += 1; ok = True; break
                j += 1
            if ok:
                while j < n and re.match(r"[a-z]", src[j], re.I):
                    j += 1
                v = src[i:j]; out.append(("regex", v)); prev = v; i = j; continue
        if c.isdigit():
            j = i
            while j < n and re.match(r"[0-9a-fx._]", src[j], re.I):
                j += 1
            v = src[i:j]; out.append(("num", v)); prev = v; i = j; continue
        if re.match(r"[A-Za-z_$]", c):
            j = i
            while j < n and re.match(r"[\w$]", src[j]):
                j += 1
            w = src[i:j]
            k = j
            while k < n and src[k] in " \t":
                k += 1
            kind = "kw" if w in _KW else ("func" if k < n and src[k] == "(" else "id")
            out.append((kind, w)); prev = w; i = j; continue
        out.append(("punc", c)); prev = c; i += 1
    return out


def highlight(src):
    """Escaped, highlighted <pre> content with line-number gutter, built entirely
    here so the browser never turns extension source into markup."""
    toks = _tokenize(src)
    lines = [[]]
    for kind, text in toks:
        if kind == "nl":
            lines.append([])
        else:
            lines[-1].append((kind, text))
    rows = []
    for li, lt in enumerate(lines, 1):
        spans = []
        for kind, text in lt:
            if kind == "ws":
                spans.append(E(text))
            else:
                cls = _COL.get(kind, "src-id")
                spans.append('<span class="%s">%s</span>' % (cls, E(text)))
        body = "".join(spans) if spans else "&#8203;"
        rows.append(
            '<span class="src-ln" aria-hidden="true">%d</span>'
            '<span class="src-code">%s</span>' % (li, body))
    return "\n".join(rows), len(lines)


# --------------------------------------------------------------------------- markup

def nav(active):
    def link(href, label, key):
        cls = ' class="active"' if key == active else ""
        return '<a href="%s"%s>%s</a>' % (href, cls, label)
    return """<nav class="nav">
  <div class="nav-inner">
    <a class="brand" href="../index.html" aria-label="nullock home">
      <img class="mark" src="../assets/favicon.svg" alt="">
      <span class="word">nullock</span>
    </a>
    <span class="mono dim" style="font-size:12.5px;letter-spacing:0.5px;">/ marketplace</span>
    <button class="nav-toggle" aria-label="Menu" onclick="document.getElementById('nav-links').classList.toggle('open')">&#9776;</button>
    <div class="nav-links" id="nav-links">
      %s
      %s
      %s
      %s
      <a class="btn btn-primary btn-sm" href="https://github.com/Bikebrainz/Nullock/releases/latest">Download</a>
    </div>
  </div>
</nav>""" % (
        link("../index.html", "Product", "product"),
        link("index.html", "Extensions", "extensions"),
        link("publish.html", "Publish", "publish"),
        link("https://github.com/Bikebrainz/Nullock", "GitHub", "github"),
    )


FOOTER = """<footer class="footer">
  <div class="f-links">
    <a href="../license.html">MIT License</a><span class="f-sep">&middot;</span>
    <a href="../security.html">Security disclosure</a><span class="f-sep">&middot;</span>
    <a href="README.md">Publishing</a><span class="f-sep">&middot;</span>
    <a href="https://github.com/Bikebrainz/Nullock">GitHub</a>
  </div>
  <div>nul&middot;lock &#9656; curated catalog &middot; rendered at build time &middot; MIT</div>
</footer>"""


def page(title, desc, active, body, depth_assets="../assets"):
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s</title>
<meta name="description" content="%s">
<meta name="theme-color" content="#0a0a0f">
<link rel="icon" type="image/svg+xml" href="%s/favicon.svg">
<link rel="stylesheet" href="%s/nullock.css">
</head>
<body>
%s
%s
%s
</body>
</html>
""" % (E(title), E(desc), depth_assets, depth_assets, nav(active), body, FOOTER)


def perm_badge(perms):
    # Neutral, not a warning. A traffic-modifying extension is a normal thing to
    # want from a pentest proxy (a request signer, a payload transformer), so the
    # badge just states the capability -- it does not flag it as risky. The
    # brand-purple badge reads as information; observe-only is a dim variant.
    modifies = len(perms) > 0
    cls = "badge" if modifies else "badge neutral"
    label = "modifies traffic" if modifies else "observe-only"
    return '<span class="%s"><span class="dot"></span>%s</span>' % (cls, E(label))


# --------------------------------------------------------------------------- pages

def build_index(exts):
    # Catalog embedded as inert JSON. The browser parses it with JSON.parse over
    # textContent -- it is never evaluated as script or written as markup. The
    # </ escape below is what keeps a "</script>" inside any string from closing
    # the block early; it is the one escape a JSON-in-<script> embed must do.
    slim = [{
        "id": e.get("id", ""),
        "name": e.get("name", ""),
        "version": e.get("version", ""),
        "author": e.get("author", ""),
        "summary": e.get("summary", ""),
        "categories": e.get("categories", []),
        "sha256": e.get("sha256", ""),
        "permissions": e.get("permissions", []),
        "updated": e.get("updated", ""),
    } for e in exts]
    catalog_json = json.dumps(slim, ensure_ascii=False).replace("</", "<\\/")

    hero = """<header class="glow-bg" style="border-bottom:1px solid var(--divider);">
  <div class="wrap-wide" style="padding:64px var(--pad-x) 40px;">
    <p class="eyebrow" style="margin:0 0 16px;">// extensions marketplace</p>
    <h1 class="h1-hero grad-text" style="max-width:19ch;">Read the source before it runs in your proxy.</h1>
    <p class="lead" style="margin-top:20px;max-width:64ch;">A curated catalog of JavaScript extensions for the Nullock proxy. Every entry pins the exact bytes to a <span class="mono" style="color:var(--purple-light);">sha256</span> and is served over https &mdash; but this site never installs anything. It exists so you can read the code first.</p>
    <div class="mkt-assure">
      <div class="mkt-assure-cell"><div class="mono" style="color:var(--purple-light);font-size:12.5px;">&#11042; sha256-pinned</div><p>Nullock hashes the download and refuses any mismatch. A missing hash fails closed.</p></div>
      <div class="mkt-assure-cell"><div class="mono" style="color:var(--purple-light);font-size:12.5px;">&#8627; https-only source</div><p>Every url resolves through <span class="mono" style="color:var(--secondary);">new URL()</span> and must be https before it is shown.</p></div>
      <div class="mkt-assure-cell"><div class="mono" style="color:var(--purple-light);font-size:12.5px;">&#10003; verified in-app</div><p>Installing happens inside Nullock, where the hash is checked. This site is for reading.</p></div>
    </div>
  </div>
</header>"""

    controls = """<div class="mkt-controls">
    <div class="mkt-search">
      <span class="mkt-search-ico mono" aria-hidden="true">&#8981;</span>
      <input id="mkt-q" type="search" placeholder="filter by name, summary, author, category&hellip;" aria-label="Filter extensions" autocomplete="off">
    </div>
    <div class="mkt-sort">
      <span class="mono dim" style="font-size:11.5px;">sort</span>
      <div class="mkt-seg" role="group" aria-label="Sort">
        <button id="sort-name" class="mkt-seg-btn is-active" type="button">name</button>
        <button id="sort-updated" class="mkt-seg-btn" type="button">updated</button>
      </div>
    </div>
  </div>
  <div class="mkt-chips" id="mkt-chips"></div>
  <div id="mkt-grid" class="mkt-grid"></div>
  <div id="mkt-empty" class="mkt-empty" hidden>
    <p class="mono muted" id="mkt-empty-label"></p>
    <button class="btn btn-ghost btn-sm" id="mkt-clear" type="button">Clear filters</button>
  </div>"""

    callout = """<div class="mkt-callout">
    <div class="mono" style="font-size:20px;color:var(--purple);line-height:1;margin-top:2px;">&#9873;</div>
    <div style="flex:1;min-width:260px;">
      <h4 style="font-size:15px;">The site is not the install path.</h4>
      <p class="muted" style="font-size:13.5px;line-height:1.6;margin:6px 0 0;max-width:80ch;">An extension runs inside the proxy and sees &mdash; and, where it declares the capability, rewrites &mdash; every request and response your browser makes. That is what they are for. Install from <span class="mono" style="color:var(--purple-light);">Settings &rarr; Marketplace</span> inside Nullock, where the download is verified against the sha256 pin above. The links here download raw source so you can read it first.</p>
    </div>
    <a class="btn btn-ghost" href="publish.html">Publish an extension &rarr;</a>
  </div>"""

    script = """<script type="application/json" id="mkt-catalog">%s</script>
<script>
(function () {
  "use strict";
  var CATALOG = JSON.parse(document.getElementById("mkt-catalog").textContent);
  var state = { q: "", cat: "all", sort: "name" };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    return n;
  }
  function fmtDate(iso) {
    if (!iso) return "";
    var m = /^(\\d{4})-(\\d{2})-(\\d{2})/.exec(iso);
    if (!m) return iso;
    var mo = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    return mo[(+m[2]) - 1] + " " + m[1];
  }
  function categories() {
    var s = [];
    CATALOG.forEach(function (e) {
      (e.categories || []).forEach(function (c) { if (s.indexOf(c) < 0) s.push(c); });
    });
    s.sort();
    return ["all"].concat(s);
  }
  function filtered() {
    var q = state.q.trim().toLowerCase();
    var out = CATALOG.filter(function (e) {
      if (state.cat !== "all" && (e.categories || []).indexOf(state.cat) < 0) return false;
      if (!q) return true;
      var hay = (e.name + " " + e.summary + " " + e.author + " " + (e.categories || []).join(" ")).toLowerCase();
      return hay.indexOf(q) >= 0;
    });
    out.sort(function (a, b) {
      return state.sort === "updated"
        ? String(b.updated || "").localeCompare(String(a.updated || ""))
        : String(a.name).localeCompare(String(b.name));
    });
    return out;
  }
  function card(e) {
    var a = el("a", "mkt-card");
    a.href = "e/" + encodeURIComponent(e.id) + ".html";  // e.id is [A-Za-z0-9._-] per the catalog gate

    var head = el("div", "mkt-card-head");
    var title = el("div", "mkt-card-title");
    title.appendChild(el("h3", null, e.name));
    title.appendChild(el("span", "mono mkt-card-ver", "v" + e.version));
    head.appendChild(title);

    var modifies = (e.permissions || []).length > 0;
    var badge = el("span", "badge" + (modifies ? "" : " neutral"));
    badge.appendChild(el("span", "dot"));
    badge.appendChild(document.createTextNode(modifies ? "modifies traffic" : "observe-only"));
    head.appendChild(badge);
    a.appendChild(head);

    a.appendChild(el("p", "mkt-card-summary", e.summary));

    var chips = el("div", "mkt-card-cats");
    (e.categories || []).forEach(function (c) { chips.appendChild(el("span", "mkt-cat", c)); });
    a.appendChild(chips);

    var foot = el("div", "mkt-card-foot");
    var sha = el("span", "mkt-sha mono");
    sha.title = "sha256:" + e.sha256;
    sha.appendChild(el("span", "mkt-sha-hex", "sha256 " + String(e.sha256).slice(0, 12) + "\\u2026"));
    foot.appendChild(sha);
    var view = el("span", "mkt-view", "View source ");
    view.appendChild(el("span", "mono", "\\u2192"));
    foot.appendChild(view);
    a.appendChild(foot);
    return a;
  }
  function renderChips() {
    var host = document.getElementById("mkt-chips");
    host.textContent = "";
    categories().forEach(function (c) {
      var b = el("button", "mkt-chip" + (state.cat === c ? " is-active" : ""), c);
      b.type = "button";
      b.addEventListener("click", function () { state.cat = c; render(); });
      host.appendChild(b);
    });
    var count = el("span", "mono dim mkt-count");
    host.appendChild(count);
    return count;
  }
  function render() {
    var count = renderChips();
    var items = filtered();
    var grid = document.getElementById("mkt-grid");
    var empty = document.getElementById("mkt-empty");
    grid.textContent = "";
    if (items.length) {
      empty.hidden = true;
      items.forEach(function (e) { grid.appendChild(card(e)); });
    } else {
      empty.hidden = false;
      document.getElementById("mkt-empty-label").textContent =
        state.q ? ('No extensions match "' + state.q + '".') : "No extensions in this category.";
    }
    count.textContent = items.length === CATALOG.length
      ? CATALOG.length + " extensions"
      : items.length + " of " + CATALOG.length + " extensions";
  }
  document.getElementById("mkt-q").addEventListener("input", function (e) { state.q = e.target.value; render(); });
  document.getElementById("mkt-clear").addEventListener("click", function () {
    state.q = ""; state.cat = "all"; document.getElementById("mkt-q").value = ""; render();
  });
  function setSort(s) {
    state.sort = s;
    document.getElementById("sort-name").classList.toggle("is-active", s === "name");
    document.getElementById("sort-updated").classList.toggle("is-active", s === "updated");
    render();
  }
  document.getElementById("sort-name").addEventListener("click", function () { setSort("name"); });
  document.getElementById("sort-updated").addEventListener("click", function () { setSort("updated"); });
  render();
})();
</script>""" % catalog_json

    body = hero + '\n<main class="wrap-wide" style="padding:34px var(--pad-x) 72px;">\n' \
        + controls + "\n" + callout + "\n</main>\n" + script
    return page(
        "Extensions — Nullock Marketplace",
        "Curated, sha256-pinned JavaScript extensions for the Nullock proxy. Read the source before it runs.",
        "extensions", body)


def build_detail(doc, e):
    ext_id = e.get("id", "")
    src = read_source(ext_id)
    perms = e.get("permissions", [])
    url = e.get("url", "")
    # The catalog url is validated the same way the app validates it: https, and
    # on the one trusted host. A bad url renders as text, never as a link.
    safe_url = url if (url.startswith("https://") and TRUSTED_HOST in url) else None

    hooks = e.get("hooks", [])
    cats = e.get("categories", [])

    meta_rows = [
        ("author", e.get("author", "")),
        ("version", "v" + e.get("version", "")),
        ("updated", fmt_date(e.get("updated", "")) or "—"),
        ("categories", ", ".join(cats)),
        ("hooks", ", ".join(hooks) or "—"),
    ]
    meta_html = "".join(
        '<div class="mkt-meta-row"><span class="mkt-meta-k mono">%s</span>'
        '<span class="mkt-meta-v">%s</span></div>' % (E(k), E(v))
        for k, v in meta_rows)

    # Permission explainer -- plain English, because "modify-requests" means
    # nothing to a reader deciding whether to trust this.
    if perms:
        perm_lines = []
        for p in perms:
            if p == "modify-requests":
                perm_lines.append("<strong>modify-requests</strong> &mdash; rewrites your requests before they reach the server. This is how a request signer, header injector or payload transformer does its job.")
            elif p == "modify-responses":
                perm_lines.append("<strong>modify-responses</strong> &mdash; rewrites responses before your browser sees them.")
            else:
                perm_lines.append("<strong>%s</strong>" % E(p))
        perm_block = ('<div class="mkt-perm"><div class="mono mkt-perm-h">capabilities</div>'
                      + "".join("<p>%s</p>" % pl for pl in perm_lines)
                      + "</div>")
    else:
        perm_block = ('<div class="mkt-perm"><div class="mono mkt-perm-h">observe-only</div>'
                      "<p>This extension declares no traffic-modifying capability. It watches requests and responses and reports findings, but does not rewrite what goes on the wire.</p></div>")

    sha = e.get("sha256", "")
    if src is not None:
        code_html, line_count = highlight(src)
        source_panel = """<div class="mkt-source">
    <div class="mkt-source-head">
      <span class="mono">%s.js</span>
      <span class="mono dim">%d lines</span>
      %s
    </div>
    <pre class="mkt-source-body"><code>%s</code></pre>
  </div>""" % (E(ext_id), line_count,
               ('<a class="btn btn-ghost btn-sm" href="%s" download>Download raw</a>' % E(safe_url)) if safe_url else '<span class="dim mono" style="font-size:12px;">no https download</span>',
               code_html)
    else:
        source_panel = '<div class="mkt-source"><div class="mkt-source-body dim mono" style="padding:24px;">// source file not found for %s</div></div>' % E(ext_id)

    dl = ('<a class="btn btn-primary" href="%s" download>Download %s.js</a>' % (E(safe_url), E(ext_id))) \
        if safe_url else '<span class="dim">No usable https download URL.</span>'

    body = """<main class="wrap-wide" style="padding:40px var(--pad-x) 72px;">
  <a href="index.html" class="mono dim" style="font-size:13px;">&larr; all extensions</a>
  <div class="mkt-detail-head">
    <div style="min-width:0;flex:1;">
      <h1 class="h1-page" style="color:var(--purple-light);">%s</h1>
      <p class="lead" style="margin-top:12px;">%s</p>
    </div>
    <div class="mkt-detail-side">
      %s
      %s
      <div class="mkt-sha-full mono" title="%s"><span style="color:var(--purple);">&#11042;</span> %s</div>
    </div>
  </div>
  <div class="mkt-cats" style="margin:18px 0 26px;">%s</div>
  %s
  %s
  <div class="mkt-install-note">
    <div class="mono" style="color:var(--purple);font-size:18px;">&#9873;</div>
    <p class="muted" style="font-size:13.5px;margin:0;">Install from <span class="mono" style="color:var(--purple-light);">Settings &rarr; Marketplace</span> inside Nullock. It verifies this exact sha256 before writing anything to disk. The download button above is for reading the source first &mdash; a file you place by hand gets no integrity check.</p>
  </div>
</main>""" % (
        E(e.get("name", ext_id)),
        E(e.get("summary", "")),
        perm_badge(perms),
        dl,
        E("sha256:" + sha), E(sha),
        "".join('<span class="mkt-cat">%s</span>' % E(c) for c in cats),
        perm_block,
        source_panel,
    )
    return page(
        "%s — Nullock Marketplace" % e.get("name", ext_id),
        e.get("summary", "")[:180],
        "extensions", body)


def build_publish(exts):
    body = """<main class="wrap-docs" style="padding:48px var(--pad-x) 72px;">
  <p class="eyebrow">// publishing</p>
  <h1 class="h1-page">Publish an extension</h1>
  <p class="lead" style="margin-top:16px;">An extension is a single JavaScript file that runs inside the Nullock proxy. Getting it into the catalog is a pull request plus one script &mdash; you never hand-edit the integrity fields.</p>

  <h2 class="h2-section" style="margin-top:44px;">1. Add a catalog entry</h2>
  <p class="muted">Open a PR against <code class="inline">extensions/marketplace.json</code> with your entry. Leave <code class="inline">sha256</code> and <code class="inline">permissions</code> empty &mdash; the sync script fills them.</p>
  <div class="code" style="margin-top:16px;">
    <div class="code-head"><span class="mono">extensions/marketplace.json</span></div>
    <pre><code>{
  "id":         "my-extension",
  "name":       "My Extension",
  "summary":    "One sentence describing what it does.",
  "version":    "0.1.0",
  "author":     "your-github-handle",
  "categories": ["scanner", "passive"],
  "url":        "https://raw.githubusercontent.com/&lt;you&gt;/&lt;repo&gt;/&lt;tag&gt;/&lt;path&gt;.js",
  "hooks":      ["nullock.onResponse"]
}</code></pre>
  </div>

  <h2 class="h2-section" style="margin-top:44px;">2. Generate the integrity fields</h2>
  <p class="muted">Run the sync script. It hashes the committed <code class="inline">.js</code>, reads the <code class="inline">// nullock:permissions</code> directive out of your source, and rewrites both fields. CI runs it with <code class="inline">--check</code> and fails the build if what you committed does not match.</p>
  <div class="code" style="margin-top:16px;">
    <div class="code-head"><span class="mono">terminal</span></div>
    <pre><code>bash scripts/marketplace_sync.sh</code></pre>
  </div>

  <h2 class="h2-section" style="margin-top:44px;">Rules that matter</h2>
  <ul class="mkt-rules">
    <li><strong>Pin the url to a tag or commit, never a branch.</strong> Branch content can change after the hash is computed, and the next person to install then gets an integrity failure.</li>
    <li><strong>Declare permissions honestly.</strong> You gain nothing by omitting them &mdash; Nullock reads the <code class="inline">// nullock:permissions</code> directive out of your script regardless, and an undeclared capability is surfaced to the user as a warning at install time.</li>
    <li><strong>Keep it to pure JS.</strong> The engine is a QJSEngine sandbox with no filesystem, no network of its own, and no npm. Anything that can rewrite traffic (<code class="inline">nullock.onRequest</code>) needs the <code class="inline">modify-requests</code> grant.</li>
    <li><strong>Add a version directive</strong> &mdash; <code class="inline">// nullock:version 0.1.0</code> &mdash; so Nullock can tell an installed copy from an update.</li>
  </ul>

  <div class="mkt-callout" style="margin-top:40px;">
    <div class="mono" style="font-size:20px;color:var(--purple);">&#9873;</div>
    <div style="flex:1;min-width:260px;">
      <h4 style="font-size:15px;">Why the sha256 is generated, not typed</h4>
      <p class="muted" style="font-size:13.5px;line-height:1.6;margin:6px 0 0;">That hash is the only thing between a compromised CDN and arbitrary code running inside someone's proxy. A hand-typed hash drifts the moment anyone touches the file, and a drifted hash breaks every install &mdash; at which point the tempting fix is to stop verifying. So it is generated and CI-checked, never authored by hand.</p>
    </div>
    <a class="btn btn-ghost" href="README.md">Full publishing docs &rarr;</a>
  </div>
</main>"""
    return page(
        "Publish — Nullock Marketplace",
        "How to publish a Nullock extension: catalog entry, generated integrity fields, and the rules that keep installs verifiable.",
        "publish", body)


# --------------------------------------------------------------------------- driver

def generate():
    doc, exts = load_catalog()
    files = {}
    files[os.path.join(OUT_DIR, "index.html")] = build_index(exts)
    files[os.path.join(OUT_DIR, "publish.html")] = build_publish(exts)
    for e in exts:
        files[os.path.join(OUT_DIR, "e", e.get("id", "") + ".html")] = build_detail(doc, e)
    return files


def main():
    check = "--check" in sys.argv[1:]
    files = generate()
    if check:
        stale = []
        for path, content in files.items():
            if not os.path.exists(path):
                stale.append(path + " (missing)")
                continue
            with io.open(path, encoding="utf-8") as f:
                if f.read() != content:
                    stale.append(path)
        # Also flag orphan detail pages for extensions no longer in the catalog.
        edir = os.path.join(OUT_DIR, "e")
        expected = {os.path.basename(p) for p in files if os.sep + "e" + os.sep in p}
        if os.path.isdir(edir):
            for name in os.listdir(edir):
                if name.endswith(".html") and name not in expected:
                    stale.append(os.path.join(edir, name) + " (orphan; extension removed from catalog)")
        if stale:
            sys.stderr.write("marketplace site is STALE:\n  " + "\n  ".join(stale) + "\n")
            sys.stderr.write("run: python scripts/marketplace_site.py\n")
            sys.exit(1)
        print("marketplace site is in sync (%d pages)" % len(files))
        return
    os.makedirs(os.path.join(OUT_DIR, "e"), exist_ok=True)
    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    print("wrote %d pages under docs/marketplace/" % len(files))
    for p in sorted(files):
        print("  " + os.path.relpath(p, ROOT))


if __name__ == "__main__":
    main()
