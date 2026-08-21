#!/usr/bin/env python3
"""Generate docs/roadmap/index.html -- the Nullock-vs-Burp parity roadmap.

WHAT THIS IS FOR. docs/roadmap/parity.json holds 409 Burp Suite capabilities,
each graded against Nullock's actual source. It is not a one-off report: it is
the ROADMAP. Everything not yet `present` or `exceeds` is the remaining work, in
priority order, and every commit that closes a gap is expected to update the
item's state here so "what's left" stays true.

THE DISCIPLINE (this is the whole point -- read before editing):
  1. Ship the feature.
  2. Edit that item in parity.json: set "state", and add a "reconciled" block
     with the date, the commit, and a one-line note on what is now true.
     Keep "audited_state" so the page can show the move.
  3. Re-run this script.
  4. CI runs --check, so a state change that is not regenerated fails the build.

Do NOT mark something `present` because it compiles or because an endpoint
exists. The original audit's bar was: reachable by a user, and handling what
Burp handles, verified by reading the code. Hold new claims to the same bar --
an inflated roadmap is worse than no roadmap, because it hides the work.

Usage:
    python scripts/parity_report.py           # regenerate the page
    python scripts/parity_report.py --check   # exit 1 if the page is stale
"""

import html
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "docs", "roadmap", "parity.json")
OUT = os.path.join(ROOT, "docs", "roadmap", "index.html")
E = html.escape

STATES = ["absent", "stub", "partial", "present", "exceeds"]
IMPACTS = ["blocker", "high", "medium", "low", "cosmetic"]
AREA_LABEL = {
    "proxy": "Proxy", "target": "Target", "scanner": "Scanner",
    "intruder": "Intruder", "repeater": "Repeater+", "sequencer": "Sessions",
    "extender": "Extender", "platform": "Platform",
}


def load():
    with io.open(DATA, encoding="utf-8") as f:
        return json.load(f)


def build(doc):
    items = doc["items"]
    counts = {s: sum(1 for i in items if i["state"] == s) for s in STATES}
    done = counts["present"] + counts["exceeds"]
    total = len(items)
    pct = round(done * 100.0 / total)
    # Newest first: a just-closed gap must land at the TOP of "Recently closed",
    # not wherever it happens to sit in parity.json's array order. Dates are ISO
    # (YYYY-MM-DD) so a string sort is chronological; a missing/blank date sorts
    # last. Python's sort is stable, so same-day closes keep their array order.
    reconciled = sorted(
        (i for i in items if "reconciled" in i),
        key=lambda i: (i.get("reconciled") or {}).get("date", ""),
        reverse=True)

    # Areas ordered worst-first: this is a roadmap, so the top of the list is
    # where the work is, not an alphabetical index.
    areas = []
    for a in sorted({i["area"] for i in items}):
        rows = [i for i in items if i["area"] == a]
        c = {s: sum(1 for r in rows if r["state"] == s) for s in STATES}
        score = (c["absent"] * 2 + c["stub"] * 1.5 + c["partial"]) / len(rows)
        areas.append({"a": a, "c": c, "n": len(rows), "score": score})
    areas.sort(key=lambda x: -x["score"])

    matrix = "".join(
        '<button class="rm-row" data-area="%s" aria-pressed="false">'
        '<span class="rm-name mono">%s</span>'
        '<span class="rm-bar">%s</span>'
        '<span class="rm-tot mono">%d</span></button>' % (
            E(o["a"]), E(AREA_LABEL.get(o["a"], o["a"])),
            "".join(
                '<i class="rm-seg s-%s" style="width:%.2f%%" title="%d %s"></i>'
                % (s, o["c"][s] * 100.0 / o["n"], o["c"][s], s)
                for s in STATES if o["c"][s]),
            o["n"])
        for o in areas)

    verdict = "".join(
        '<div class="rm-cell"><span class="rm-num s-%s">%d</span>'
        '<span class="rm-lab mono">%s</span></div>' % (s, counts[s], s)
        for s in STATES)
    verdict += ('<div class="rm-cell"><span class="rm-num">%d%%</span>'
                '<span class="rm-lab mono">at parity</span></div>' % pct)

    recent = ""
    if reconciled:
        RECENT_CAP = 24  # a genuine "recent" window, not the full 180+ backlog
        shown = reconciled[:RECENT_CAP]
        rows = "".join(
            '<li><span class="mono rm-commit">%s</span> '
            '<span class="mono rm-date">%s</span> <strong>%s</strong>'
            '%s<br><span class="muted">%s</span></li>' % (
                E(i["reconciled"].get("commit", "")),
                E(i["reconciled"].get("date", "")),
                E(i["feature"][:90]),
                (' <span class="rm-move mono">%s &rarr; %s</span>'
                 % (E(i.get("audited_state", "")), E(i["state"])))
                if i.get("audited_state") else "",
                E(i["reconciled"].get("note", "")))
            for i in shown)
        # Honest cap: say how many are shown of the total, and point at the full
        # list rather than silently truncating.
        cap_note = ("" if len(reconciled) <= RECENT_CAP else
                    " Showing the %d most recent of %d reconciled since the audit; "
                    "the full set is in the capability table below." % (RECENT_CAP, len(reconciled)))
        recent = ("""<section class="panel">
    <h2>Recently closed</h2>
    <p class="muted" style="font-size:13.5px;">Gaps reconciled since the audit, newest first, each with the date and the commit that made it true.%s</p>
    <ul class="rm-recent">%s</ul>
  </section>""" % (cap_note, rows))

    payload = json.dumps(
        [{"a": i["area"], "f": i["feature"], "s": i["state"],
          "i": i["impact"], "e": i["effort"], "g": i.get("gap", ""),
          "w": i.get("why", ""), "v": i.get("evidence", ""),
          "o": i.get("audited_state", ""),
          "r": (i.get("reconciled") or {}).get("note", "")}
         for i in items],
        separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Roadmap &mdash; Nullock vs Burp Suite</title>
<meta name="description" content="Every Burp Suite capability graded against Nullock's source, kept current as gaps close. The remaining items are the roadmap.">
<meta name="theme-color" content="#0a0a0f">
<link rel="icon" type="image/svg+xml" href="../assets/favicon.svg">
<link rel="stylesheet" href="../assets/nullock.css">
</head>
<body>
<nav class="nav">
  <div class="nav-inner">
    <a class="brand" href="../index.html" aria-label="nullock home">
      <img class="mark" src="../assets/favicon.svg" alt="">
      <span class="word">nullock</span>
    </a>
    <span class="mono dim" style="font-size:12.5px;letter-spacing:0.5px;">/ roadmap</span>
    <button class="nav-toggle" aria-label="Menu" onclick="document.getElementById('nav-links').classList.toggle('open')">&#9776;</button>
    <div class="nav-links" id="nav-links">
      <a href="../index.html">Product</a>
      <a href="../docs/index.html">Docs</a>
      <a href="../marketplace/index.html">Extensions</a>
      <a href="../labs/index.html">Labs</a>
      <a href="../roadmap/index.html" class="active">Roadmap</a>
      <a href="../pricing.html">Pricing</a>
      <a href="../changelog.html">Changelog</a>
      <a href="../about.html">About</a>
      <a href="https://github.com/Bikebrainz/Nullock" class="github">GitHub</a>
      <a href="../index.html#download" class="btn btn-primary btn-sm">Download</a>
    </div>
  </div>
</nav>

<header class="glow-bg" style="border-bottom:1px solid var(--divider);">
  <div class="wrap-wide" style="padding:60px var(--pad-x) 36px;">
    <p class="eyebrow" style="margin:0 0 16px;">// parity roadmap</p>
    <h1 class="h1-hero grad-text" style="max-width:20ch;">Every Burp feature, graded against our source.</h1>
    <p class="lead" style="margin-top:20px;max-width:66ch;">%d Burp Suite capabilities, each checked against Nullock's actual code rather than its documentation, then re-checked by an adversarial pass whose only job was to disprove the first. Whatever is not yet <span class="mono" style="color:var(--ok);">present</span> is the work that remains &mdash; this page is the roadmap, and it is updated as each gap closes.</p>
  </div>
</header>

<main class="wrap-wide" style="padding:30px var(--pad-x) 72px;display:flex;flex-direction:column;gap:30px;">

  <section class="rm-verdict">%s</section>

  <section class="panel">
    <h2>Where the work is</h2>
    <p class="muted" style="font-size:13.5px;">One bar per functional area, ordered worst-first. Click an area to filter the register.</p>
    <div class="rm-matrix">%s</div>
    <div class="rm-legend">%s</div>
  </section>

  %s

  <section class="panel">
    <h2>Register</h2>
    <div class="rm-bar-row">
      <input type="search" id="rm-q" placeholder="search features, gaps, evidence&hellip;" aria-label="Search features">
      <span class="mono dim" id="rm-count"></span>
    </div>
    <div class="rm-bar-row" id="rm-filters"></div>
    <div id="rm-rows" class="rm-rows"></div>
  </section>

  <section class="panel">
    <h2>How this stays true</h2>
    <p class="muted" style="font-size:14px;line-height:1.7;">The data lives in <code class="inline">docs/roadmap/parity.json</code> and this page is generated from it by <code class="inline">scripts/parity_report.py</code>. When a commit closes a gap it updates that item's state and records the commit, then regenerates &mdash; and CI fails the build if the committed page has drifted from the data. The bar for calling something <span class="mono" style="color:var(--ok);">present</span> is the same one the audit used: reachable by a real user, handling what Burp handles, verified by reading the code. An inflated roadmap would be worse than none, because it hides the work.</p>
  </section>
</main>

<footer class="footer">
  <div class="f-links">
    <a href="../index.html">Product</a><span class="f-sep">&middot;</span>
    <a href="../marketplace/index.html">Extensions</a><span class="f-sep">&middot;</span>
    <a href="https://github.com/Bikebrainz/Nullock">GitHub</a>
  </div>
  <div>nul&middot;lock &#9656; audited %s &middot; reconciled through %s &middot; generated from parity.json</div>
</footer>

<script type="application/json" id="rm-data">%s</script>
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("rm-data").textContent);
  var STATES = %s;
  var IMPACTS = %s;
  var AREA = %s;
  var f = { area: null, state: null, impact: null, q: "" };

  function el(t, c, x) { var n = document.createElement(t); if (c) n.className = c; if (x != null) n.textContent = String(x); return n; }

  function chips() {
    var host = document.getElementById("rm-filters");
    host.textContent = "";
    function mk(label, key, val) {
      var b = el("button", "rm-chip" + (f[key] === val ? " is-active" : ""), label);
      b.type = "button";
      b.addEventListener("click", function () { f[key] = (f[key] === val ? null : val); render(); });
      host.appendChild(b);
    }
    IMPACTS.forEach(function (i) { mk(i, "impact", i); });
    host.appendChild(el("span", "rm-gap"));
    STATES.forEach(function (s) { mk(s, "state", s); });
  }

  function render() {
    chips();
    var rank = {}; IMPACTS.forEach(function (v, i) { rank[v] = i; });
    var q = f.q.trim().toLowerCase();
    var rows = DATA.filter(function (d) {
      if (f.area && d.a !== f.area) return false;
      if (f.state && d.s !== f.state) return false;
      if (f.impact && d.i !== f.impact) return false;
      if (q && (d.f + " " + d.g + " " + d.w + " " + d.v).toLowerCase().indexOf(q) < 0) return false;
      return true;
    }).sort(function (x, y) {
      return (rank[x.i] - rank[y.i]) || (STATES.indexOf(x.s) - STATES.indexOf(y.s));
    });

    document.getElementById("rm-count").textContent = rows.length + " of " + DATA.length;
    var host = document.getElementById("rm-rows");
    host.textContent = "";
    if (!rows.length) { host.appendChild(el("div", "rm-empty mono", "nothing matches that filter")); return; }

    rows.forEach(function (d) {
      var art = el("article", "rm-item imp-" + d.i);
      var head = el("button", "rm-head");
      head.type = "button";
      head.setAttribute("aria-expanded", "false");
      head.appendChild(el("span", "rm-feat", d.f));
      head.appendChild(el("span", "rm-area mono", AREA[d.a] || d.a));
      head.appendChild(el("span", "rm-meta mono", d.i + " \\u00b7 " + d.e));
      head.appendChild(el("span", "rm-pill mono s-" + d.s, d.s));
      art.appendChild(head);

      var body = el("div", "rm-body"); body.hidden = true;
      if (d.o && d.o !== d.s) {
        body.appendChild(el("div", "rm-moved mono", "closed since audit: " + d.o + " \\u2192 " + d.s));
      }
      if (d.r) { var p0 = el("p", "rm-note", d.r); body.appendChild(p0); }
      if (d.g) { body.appendChild(el("h4", null, "Gap")); body.appendChild(el("p", null, d.g)); }
      if (d.w) { body.appendChild(el("h4", null, "Verification")); body.appendChild(el("p", null, d.w)); }
      if (d.v) { body.appendChild(el("h4", null, "Evidence")); body.appendChild(el("div", "rm-ev mono", d.v)); }
      art.appendChild(body);

      head.addEventListener("click", function () {
        var open = !body.hidden;
        body.hidden = open;
        head.setAttribute("aria-expanded", String(!open));
      });
      host.appendChild(art);
    });
  }

  document.querySelectorAll(".rm-row").forEach(function (b) {
    b.addEventListener("click", function () {
      var a = b.dataset.area;
      f.area = (f.area === a) ? null : a;
      document.querySelectorAll(".rm-row").forEach(function (x) {
        x.setAttribute("aria-pressed", String(x.dataset.area === f.area));
      });
      render();
    });
  });
  document.getElementById("rm-q").addEventListener("input", function (e) { f.q = e.target.value; render(); });
  render();
})();
</script>
</body>
</html>
""" % (
        total, verdict, matrix,
        "".join('<span><i class="rm-dot s-%s"></i>%s</span>' % (s, s) for s in STATES),
        recent,
        E(doc.get("audit_date", "")), E(doc.get("reconciled_through", "")),
        payload,
        json.dumps(STATES), json.dumps(IMPACTS), json.dumps(AREA_LABEL),
    )


def main():
    doc = load()
    page = build(doc)
    if "--check" in sys.argv[1:]:
        if not os.path.exists(OUT):
            sys.stderr.write("roadmap page missing: %s\nrun: python scripts/parity_report.py\n" % OUT)
            sys.exit(1)
        with io.open(OUT, encoding="utf-8") as fh:
            if fh.read() != page:
                sys.stderr.write(
                    "roadmap page is STALE against docs/roadmap/parity.json\n"
                    "run: python scripts/parity_report.py\n")
                sys.exit(1)
        print("roadmap is in sync (%d features)" % len(doc["items"]))
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with io.open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)
    n = len(doc["items"])
    done = sum(1 for i in doc["items"] if i["state"] in ("present", "exceeds"))
    print("wrote %s (%d features, %d at parity = %d%%)"
          % (os.path.relpath(OUT, ROOT), n, done, round(done * 100.0 / n)))


if __name__ == "__main__":
    main()
