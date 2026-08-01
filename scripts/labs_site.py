#!/usr/bin/env python3
"""Generate the static Labs site under docs/labs/ from the labs/ directory.

Nullock Labs are 50 intentionally-vulnerable apps for practicing with the tool.
This builds a browsable catalog + a per-lab walkthrough page, generated so every
field (all of it authored in the repo, but still) is HTML-escaped once at build
time -- same no-runtime-string-to-HTML guarantee the marketplace and roadmap
generators give.

Data sources, all already in the repo:
  labs/README.md                  the canonical lab list: slug, one-line vuln, port
  labs/<slug>/app.py              module docstring -> title, description,
                                  walkthrough steps, the fix note
  labs/<slug>/.nullock-project.json  the pre-set scope

Run:
    python scripts/labs_site.py           # regenerate
    python scripts/labs_site.py --check   # exit 1 if the committed pages are stale

CI runs --check, so a lab added/renamed without regenerating fails the build.
"""

import html
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, "labs")
OUT = os.path.join(ROOT, "docs", "labs")
E = html.escape

# Coarse categories inferred from the slug, so the catalog can filter by class.
# Order matters: first matching keyword wins.
CATEGORY_RULES = [
    ("Injection", ("sqli", "ssti", "command-injection", "nosql", "xxe",
                   "crlf", "csv-injection", "graphql", "deserialization",
                   "prototype-pollution", "param-pollution")),
    ("Access control", ("idor", "broken-access", "mass-assignment",
                        "verb-tamper", "2fa", "dangerous-http-methods")),
    ("Authentication", ("jwt", "oauth", "session-fixation", "user-enumeration",
                        "weak-reset", "reset-token", "predictable-session",
                        "credentials-in-url", "rate-limit")),
    ("SSRF & fetch", ("ssrf",)),
    ("Client-side", ("xss", "csrf", "clickjacking", "cors", "open-redirect",
                     "cache-deception", "cache-poisoning", "host-header",
                     "insecure-cookie", "missing-security-headers")),
    ("Info disclosure", ("secret-exposure", "verbose-errors", "directory-listing",
                         "sensitive-file", "robots", "file-upload")),
    ("Business logic", ("race-condition", "business-logic")),
]


def category(slug):
    for name, kws in CATEGORY_RULES:
        if any(k in slug for k in kws):
            return name
    return "Other"


# --------------------------------------------------------------------------- data

def parse_readme():
    """Pull (slug, vuln, port) from the fenced list in labs/README.md."""
    text = io.open(os.path.join(LABS, "README.md"), encoding="utf-8").read()
    rows = {}
    # e.g. "  01-xss-mirror/      # Reflected XSS ...    (5001)"
    rx = re.compile(r"^\s*(\d\d-[a-z0-9-]+)/\s*#\s*(.*?)\s*\((\d{4})\)\s*$", re.M)
    for m in rx.finditer(text):
        slug, vuln, port = m.group(1), m.group(2).strip(), m.group(3)
        rows[slug] = {"slug": slug, "vuln": vuln, "port": port}
    return rows


def parse_docstring(slug):
    """Extract title / description / steps / fix from a lab's app.py docstring."""
    path = os.path.join(LABS, slug, "app.py")
    if not os.path.exists(path):
        return {}
    src = io.open(path, encoding="utf-8", errors="replace").read()
    m = re.match(r'\s*(?:"""|\'\'\')(.*?)(?:"""|\'\'\')', src, re.S)
    if not m:
        return {}
    doc = m.group(1).strip("\n")
    lines = doc.split("\n")

    title = ""
    if lines:
        first = lines[0].strip()
        first = re.sub(r"^Lab\s+\d+\s*--\s*", "", first).rstrip(".")
        title = first

    # description = paragraph(s) between the title line and the "Run:" block
    body = "\n".join(lines[1:])
    desc = ""
    run_split = re.split(r"\n\s*Run:\s*\n", body, maxsplit=1)
    before_run = run_split[0].strip()
    # description is everything before Run: that is not itself a heading
    desc = " ".join(p.strip() for p in before_run.split("\n") if p.strip())

    # A remediation note may be phrased "Fix:", "The fix ...", "Mitigation:",
    # "Remediation:". It can sit right after the last walkthrough step with no
    # blank line, so it must both END the step list and be pulled out as its own
    # field -- otherwise it gets glued onto the last step as a continuation.
    fix_start = re.compile(r"^(?:the\s+fix|fix|mitigation|remediation)\b[:\s]",
                           re.I)

    # steps = the numbered list under "In Nullock:", stopping at a fix line.
    steps = []
    fix = ""
    mstep = re.search(r"In Nullock:\s*\n(.*?)(?:\n\s*\n|$)", body, re.S)
    if mstep:
        in_fix = False
        fix_lines = []
        for ln in mstep.group(1).split("\n"):
            s = ln.strip()
            if not s:
                continue
            if fix_start.match(s):
                in_fix = True
            if in_fix:
                fix_lines.append(s)
                continue
            sm = re.match(r"^\d+\.\s*(.*)$", s)
            if sm:
                steps.append(sm.group(1).strip())
            elif steps:
                steps[-1] += " " + s   # continuation of the previous step
        if fix_lines:
            fix = " ".join(fix_lines).strip()

    # Fall back to a fix paragraph anywhere in the docstring (some labs put it
    # after a blank line rather than inside the steps block).
    if not fix:
        mfix = re.search(r"((?:The\s+fix|Fix|Mitigation|Remediation)\b[:\s][^\n]*"
                         r"(?:\n[^\n]+)*)", body, re.I)
        if mfix:
            fix = " ".join(x.strip() for x in mfix.group(1).split("\n")).strip()

    return {"title": title, "desc": desc, "steps": steps, "fix": fix}


def read_scope(slug):
    path = os.path.join(LABS, slug, ".nullock-project.json")
    if not os.path.exists(path):
        return []
    try:
        return json.load(io.open(path, encoding="utf-8")).get("inScope", [])
    except Exception:
        return []


def load():
    readme = parse_readme()
    labs = []
    for slug in sorted(readme):
        d = dict(readme[slug])
        d["num"] = slug.split("-", 1)[0]
        d["category"] = category(slug)
        d.update({k: v for k, v in parse_docstring(slug).items()})
        d["scope"] = read_scope(slug)
        labs.append(d)
    return labs


# --------------------------------------------------------------------------- markup

def nav(active):
    return """<nav class="nav">
  <div class="nav-inner">
    <a class="brand" href="../index.html" aria-label="nullock home">
      <img class="mark" src="../assets/favicon.svg" alt="">
      <span class="word">nullock</span>
    </a>
    <span class="mono dim" style="font-size:12.5px;letter-spacing:0.5px;">/ labs</span>
    <button class="nav-toggle" aria-label="Menu" onclick="document.getElementById('nav-links').classList.toggle('open')">&#9776;</button>
    <div class="nav-links" id="nav-links">
      <a href="../index.html">Product</a>
      <a href="../docs/index.html">Docs</a>
      <a href="../marketplace/index.html">Extensions</a>
      <a href="index.html"%s>Labs</a>
      <a href="../roadmap/index.html">Roadmap</a>
      <a class="btn btn-primary btn-sm" href="https://github.com/Bikebrainz/Nullock/releases/latest">Download</a>
    </div>
  </div>
</nav>""" % (' class="active"' if active == "labs" else "")


FOOTER = """<footer class="footer">
  <div class="f-links">
    <a href="../index.html">Product</a><span class="f-sep">&middot;</span>
    <a href="../marketplace/index.html">Extensions</a><span class="f-sep">&middot;</span>
    <a href="../roadmap/index.html">Roadmap</a><span class="f-sep">&middot;</span>
    <a href="https://github.com/Bikebrainz/Nullock/tree/Nullock/labs">Source</a>
  </div>
  <div>nul&middot;lock &#9656; 50 intentionally-vulnerable targets &middot; run them on localhost &middot; MIT</div>
</footer>"""


def page(title, desc, active, body):
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s</title>
<meta name="description" content="%s">
<meta name="theme-color" content="#0a0a0f">
<link rel="icon" type="image/svg+xml" href="../assets/favicon.svg">
<link rel="stylesheet" href="../assets/nullock.css">
</head>
<body>
%s
%s
%s
</body>
</html>
""" % (E(title), E(desc), nav(active), body, FOOTER)


def build_index(labs):
    slim = [{"slug": l["slug"], "num": l["num"], "title": l.get("title", "") or l["slug"],
             "vuln": l.get("vuln", ""), "port": l["port"], "cat": l["category"],
             "steps": len(l.get("steps", []))} for l in labs]
    payload = json.dumps(slim, ensure_ascii=False).replace("</", "<\\/")
    cats = sorted({l["category"] for l in labs})

    hero = """<header class="glow-bg" style="border-bottom:1px solid var(--divider);">
  <div class="wrap-wide" style="padding:60px var(--pad-x) 36px;">
    <p class="eyebrow" style="margin:0 0 16px;">// nullock labs</p>
    <h1 class="h1-hero grad-text" style="max-width:18ch;">Fifty bugs to break, on your own machine.</h1>
    <p class="lead" style="margin-top:20px;max-width:64ch;">Each lab is one self-contained Python app with a known vulnerability and a walkthrough that ends in a Nullock finding. Run it on localhost, point Nullock at it, and confirm the bug with the same probe you would use on a real target.</p>
    <div class="labs-start mono">
      <span class="dim">$</span> git clone the repo &middot; <span class="dim">$</span> pip install flask &middot; <span class="dim">$</span> python labs/&lt;slug&gt;/app.py
    </div>
  </div>
</header>"""

    controls = """<div class="labs-controls">
    <div class="labs-search">
      <span class="labs-search-ico mono" aria-hidden="true">&#8981;</span>
      <input id="labs-q" type="search" placeholder="filter by name, bug class, port&hellip;" aria-label="Filter labs" autocomplete="off">
    </div>
  </div>
  <div class="labs-chips" id="labs-chips"></div>
  <div id="labs-grid" class="labs-grid"></div>
  <div id="labs-empty" class="labs-empty" hidden><p class="mono muted">No labs match that filter.</p></div>"""

    script = """<script type="application/json" id="labs-data">%s</script>
<script>
(function () {
  "use strict";
  var LABS = JSON.parse(document.getElementById("labs-data").textContent);
  var state = { q: "", cat: "all" };
  function el(t, c, x) { var n = document.createElement(t); if (c) n.className = c; if (x != null) n.textContent = String(x); return n; }
  function cats() {
    var s = []; LABS.forEach(function (l) { if (s.indexOf(l.cat) < 0) s.push(l.cat); });
    s.sort(); return ["all"].concat(s);
  }
  function filtered() {
    var q = state.q.trim().toLowerCase();
    return LABS.filter(function (l) {
      if (state.cat !== "all" && l.cat !== state.cat) return false;
      if (!q) return true;
      return (l.title + " " + l.vuln + " " + l.port + " " + l.cat).toLowerCase().indexOf(q) >= 0;
    });
  }
  function card(l) {
    var a = el("a", "labs-card");
    a.href = encodeURIComponent(l.slug) + ".html";  // slug is [0-9a-z-] from the README
    var top = el("div", "labs-card-top");
    top.appendChild(el("span", "labs-num mono", l.num));
    top.appendChild(el("span", "labs-cat mono", l.cat));
    top.appendChild(el("span", "labs-port mono", ":" + l.port));
    a.appendChild(top);
    a.appendChild(el("h3", "labs-title", l.title));
    a.appendChild(el("p", "labs-vuln", l.vuln));
    var foot = el("div", "labs-foot mono");
    foot.appendChild(el("span", null, l.steps + "-step walkthrough"));
    foot.appendChild(el("span", "labs-go", "Open \\u2192"));
    a.appendChild(foot);
    return a;
  }
  function renderChips() {
    var host = document.getElementById("labs-chips"); host.textContent = "";
    cats().forEach(function (c) {
      var b = el("button", "labs-chip" + (state.cat === c ? " is-active" : ""), c);
      b.type = "button";
      b.addEventListener("click", function () { state.cat = c; render(); });
      host.appendChild(b);
    });
    var count = el("span", "mono dim labs-count"); host.appendChild(count); return count;
  }
  function render() {
    var count = renderChips();
    var items = filtered();
    var grid = document.getElementById("labs-grid");
    var empty = document.getElementById("labs-empty");
    grid.textContent = "";
    if (items.length) { empty.hidden = true; items.forEach(function (l) { grid.appendChild(card(l)); }); }
    else empty.hidden = false;
    count.textContent = items.length === LABS.length ? LABS.length + " labs" : items.length + " of " + LABS.length + " labs";
  }
  document.getElementById("labs-q").addEventListener("input", function (e) { state.q = e.target.value; render(); });
  render();
})();
</script>""" % payload

    body = hero + '\n<main class="wrap-wide" style="padding:34px var(--pad-x) 72px;">\n' + controls + "\n" + script + "\n</main>"
    return page("Labs — Nullock", "Fifty intentionally-vulnerable apps for practicing with Nullock. Run them on localhost and confirm each bug with the tool.", "labs", body)


def build_detail(l):
    steps = l.get("steps", [])
    steps_html = ""
    if steps:
        steps_html = ('<ol class="labs-steps">'
                      + "".join("<li>%s</li>" % E(s) for s in steps)
                      + "</ol>")
    else:
        steps_html = '<p class="muted">See the app.py docstring for the walkthrough.</p>'

    scope = l.get("scope", [])
    scope_html = ""
    if scope:
        scope_html = ('<div class="labs-scope"><div class="mono labs-scope-h">pre-set scope</div>'
                      + "".join('<code class="inline">%s</code>' % E(s) for s in scope)
                      + '</div>')

    fix = ('<div class="labs-fix"><div class="mono labs-fix-h">the fix</div><p>%s</p></div>'
           % E(l["fix"])) if l.get("fix") else ""

    run = ("python labs/%s/app.py" % l["slug"])

    body = """<main class="wrap-docs" style="padding:44px var(--pad-x) 72px;">
  <a href="index.html" class="mono dim" style="font-size:13px;">&larr; all labs</a>
  <div class="labs-detail-head">
    <span class="labs-num mono">%s</span>
    <span class="labs-cat mono">%s</span>
    <span class="labs-port mono">localhost:%s</span>
  </div>
  <h1 class="h1-page" style="margin-top:14px;">%s</h1>
  <p class="lead" style="margin-top:12px;">%s</p>

  <div class="code" style="margin-top:26px;">
    <div class="code-head"><span class="mono">start the lab</span></div>
    <pre><code>pip install flask
%s
# then open http://localhost:%s/</code></pre>
  </div>

  %s

  <h2 class="h2-section" style="margin-top:40px;font-size:22px;">Walkthrough</h2>
  %s

  %s

  <div class="labs-note">
    <div class="mono" style="color:var(--purple);font-size:18px;">&#9873;</div>
    <p class="muted" style="font-size:13.5px;margin:0;">Every lab maps to a Nullock probe, so you learn the bug class and how to confirm it with the tool. The scope above is pre-set to the lab host, so active probes only ever fire at the lab &mdash; never at anything else you have open.</p>
  </div>
</main>""" % (
        E(l["num"]), E(l["category"]), E(l["port"]),
        E(l.get("title", "") or l["slug"]),
        E(l.get("desc", "") or l.get("vuln", "")),
        E(run), E(l["port"]),
        scope_html,
        steps_html,
        fix,
    )
    return page("%s — Nullock Labs" % (l.get("title", "") or l["slug"]),
                (l.get("vuln", "") or "")[:180], "labs", body)


# --------------------------------------------------------------------------- driver

def generate():
    labs = load()
    files = {os.path.join(OUT, "index.html"): build_index(labs)}
    for l in labs:
        files[os.path.join(OUT, l["slug"] + ".html")] = build_detail(l)
    return files, labs


def main():
    files, labs = generate()
    if "--check" in sys.argv[1:]:
        stale = []
        for path, content in files.items():
            if not os.path.exists(path):
                stale.append(path + " (missing)")
            else:
                with io.open(path, encoding="utf-8") as f:
                    if f.read() != content:
                        stale.append(path)
        expected = {os.path.basename(p) for p in files}
        if os.path.isdir(OUT):
            for name in os.listdir(OUT):
                if name.endswith(".html") and name not in expected:
                    stale.append(os.path.join(OUT, name) + " (orphan; lab removed)")
        if stale:
            sys.stderr.write("labs site is STALE:\n  " + "\n  ".join(stale) + "\n")
            sys.stderr.write("run: python scripts/labs_site.py\n")
            sys.exit(1)
        print("labs site is in sync (%d pages)" % len(files))
        return
    os.makedirs(OUT, exist_ok=True)
    for path, content in files.items():
        with io.open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    expected = {os.path.basename(p) for p in files}
    removed = []
    for name in sorted(os.listdir(OUT)):
        if name.endswith(".html") and name not in expected:
            os.remove(os.path.join(OUT, name)); removed.append(name)
    print("wrote %d labs pages (%d labs)" % (len(files), len(labs)))
    for name in removed:
        print("  removed orphan " + name)


if __name__ == "__main__":
    main()
