# Nullock brand system

Everything you need to build a clean website / app on top of the Nullock
identity. Color tokens, typography, components, voice. All free to copy
into Tailwind config / CSS variables / Figma library.

## Color tokens

### Core palette

```
--purple-50    #f3eaff   light accents, hover halos
--purple-200   #d4b9ff   text on dark, headings
--purple-400   #b7a3d6   links, secondary headings
--purple-500   #9d4edd   brand primary; CTAs, badges
--purple-700   #5a189a   gradient end, hover states
--purple-900   #3a0f6b   dark CTA hover

--bg-0         #0d0d12   page background
--bg-1         #14141a   card / surface
--bg-2         #1c1c24   raised surface, code blocks
--bg-3         #161020   featured card (subtle purple tint)

--line-0       #1c1c24   subtle divider
--line-1       #2a2a35   stronger divider, card border
--line-2       #3a3a4a   active / focus ring

--text-0       #d0d0d6   primary copy
--text-1       #a0a0a8   secondary copy
--text-2       #888      dim caption
--text-3       #555      footer
--text-strong  #fff      hero headlines

--ok           #4ade80   success / green checks
--warn         #fbbf24   caution / "limited" badges
--err          #f87171   errors / refunds
```

### Brand gradient

```css
background: linear-gradient(135deg, #9d4edd 0%, #5a189a 100%);
/* hero text variant */
background: linear-gradient(135deg, #d4b9ff 0%, #9d4edd 50%, #5a189a 100%);
-webkit-background-clip: text;
-webkit-text-fill-color: transparent;
```

Apply to: primary CTAs, hero headlines, brand mark, gradient borders on featured cards.

## Typography

### Stack

```css
font-family: -apple-system, BlinkMacSystemFont, system-ui,
             "Inter", "Segoe UI", Roboto, sans-serif;
font-family: ui-monospace, "SF Mono", "JetBrains Mono", Consolas, monospace;
```

System stack is intentional -- no web font load, no FOUT, no CDN dependency. If you upgrade to a custom font, **Inter** at 400/600/700 is the right pick.

### Scale

| Use | Size | Weight | Line height | Letter spacing |
|---|---|---|---|---|
| Hero h1 | 52px | 700 | 1.1 | -1.5px |
| Section h2 | 28px | 700 | 1.2 | -0.5px |
| Card h3 | 18px | 600 | 1.3 | normal |
| Body | 15px | 400 | 1.6 | normal |
| Small / caption | 13px | 400 | 1.5 | normal |
| Code inline | 12.5px | 400 | 1.5 | normal |
| Code block | 13px | 400 | 1.5 | normal |

## Layout

- Max content width: **920px** (marketing pages), **800px** (docs), **1080px** (pricing matrix)
- Page horizontal padding: **32px** desktop, **20px** mobile
- Section vertical rhythm: **60px** between sections, **32px** between subsections
- Card padding: **20px** standard, **24px** featured
- Card border radius: **6-8px**
- Button padding: **13px 24px** large, **8px 14px** small
- Button border radius: **6px**

## Component library

Copy-paste-ready CSS. Drop into any new page.

### Button

```html
<a class="btn primary" href="#">Primary action</a>
<a class="btn ghost" href="#">Secondary action</a>
```

```css
.btn {
  display: inline-block;
  padding: 13px 24px;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  cursor: pointer;
  transition: transform 80ms ease, filter 80ms ease;
  border: none;
}
.btn:hover { transform: translateY(-1px); filter: brightness(1.1); }
.btn.primary {
  background: linear-gradient(135deg, #9d4edd 0%, #5a189a 100%);
  color: #fff;
}
.btn.ghost {
  background: transparent;
  color: #d0d0d6;
  border: 1px solid #2a2a35;
}
.btn.ghost:hover { border-color: #9d4edd; color: #d4b9ff; }
```

### Card

```html
<div class="card">
  <h3>Card title</h3>
  <p>Card body copy.</p>
</div>

<div class="card featured">  <!-- gradient ring for featured -->
  <h3>Featured</h3>
</div>
```

```css
.card {
  background: #14141a;
  border: 1px solid #2a2a35;
  border-radius: 8px;
  padding: 20px;
}
.card h3 { margin: 0 0 8px; color: #d4b9ff; font-size: 18px; }
.card p  { margin: 0; color: #b0b0b8; font-size: 13.5px; }
.card.featured {
  border-color: #9d4edd;
  background: #161020;
  box-shadow: 0 0 0 1px #9d4edd inset;
}
```

### Badge

```html
<span class="badge">cool</span>
<span class="badge warn">limited</span>
<span class="badge ok">live</span>
```

```css
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  background: #1c1c24;
  color: #d4b9ff;
  font-weight: 500;
}
.badge.warn { color: #fbbf24; background: #2a2010; }
.badge.ok   { color: #4ade80; background: #102a18; }
```

### Input

```html
<input type="text" placeholder="Search..." />
<label class="field">
  <span>Email</span>
  <input type="email" placeholder="you@example.com" />
</label>
```

```css
input, textarea, select {
  background: #1c1c24;
  color: #d0d0d6;
  border: 1px solid #2a2a35;
  border-radius: 6px;
  padding: 8px 12px;
  font-family: inherit;
  font-size: 13.5px;
  width: 100%;
}
input:focus, textarea:focus, select:focus {
  outline: none;
  border-color: #9d4edd;
  box-shadow: 0 0 0 3px rgba(157, 78, 221, 0.2);
}
.field { display: block; margin-bottom: 16px; }
.field > span {
  display: block;
  color: #888;
  font-size: 12px;
  margin-bottom: 4px;
}
```

### Code block

```html
<pre><code>nullock status</code></pre>
```

```css
pre {
  background: #1c1c24;
  border: 1px solid #2a2a35;
  border-radius: 6px;
  padding: 14px 16px;
  overflow-x: auto;
  font: 13px/1.5 ui-monospace, Consolas, monospace;
  color: #d4b9ff;
}
code { font: 12.5px/1.5 ui-monospace, Consolas, monospace; }
:not(pre) > code {
  background: #1c1c24;
  padding: 1px 5px;
  border-radius: 3px;
  color: #d4b9ff;
}
```

### Table

```html
<table class="data">
  <thead><tr><th>Col</th><th>Col</th></tr></thead>
  <tbody><tr><td>cell</td><td>cell</td></tr></tbody>
</table>
```

```css
table.data {
  width: 100%;
  border-collapse: collapse;
  font-size: 13.5px;
}
table.data th {
  text-align: left;
  padding: 10px 14px;
  color: #888;
  font-weight: 600;
  font-size: 12px;
  border-bottom: 1px solid #2a2a35;
}
table.data td {
  padding: 10px 14px;
  border-bottom: 1px solid #1c1c24;
  color: #b0b0b8;
}
table.data tbody tr:hover { background: #14141a; }
```

### Nav bar

```html
<nav class="topnav">
  <div class="brand">Nullock</div>
  <div class="links">
    <a href="#">Docs</a>
    <a href="#">Pricing</a>
    <a class="cta" href="#">Get started</a>
  </div>
</nav>
```

```css
.topnav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 32px;
  border-bottom: 1px solid #1c1c24;
  position: sticky;
  top: 0;
  background: rgba(13, 13, 18, 0.92);
  backdrop-filter: blur(10px);
  z-index: 10;
}
.topnav .brand {
  font-size: 18px;
  font-weight: 700;
  background: linear-gradient(135deg, #9d4edd 0%, #5a189a 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.topnav .links a { color: #999; font-size: 13px; margin-left: 24px; text-decoration: none; }
.topnav .links a:hover { color: #fff; }
.topnav .links a.cta {
  color: #fff;
  background: linear-gradient(135deg, #9d4edd 0%, #5a189a 100%);
  padding: 8px 14px;
  border-radius: 6px;
}
```

## Voice + tone

Write the way I commit. Examples are real.

**Direct, not breathless.**
- Bad: *"Revolutionizing web security with AI-powered, blockchain-validated, quantum-ready scanning."*
- Good: *"MITM proxy + repeater + intruder + scanner + OAST in one binary."*

**Honest about limitations.**
- Bad: *"Nullock outperforms every commercial scanner."*
- Good: *"We have ~10 detectors. Burp Pro has hundreds. Difference matters; pick the right tool."*

**Numbered where it helps.**
- Bad: *"Lightning-fast handling of huge histories."*
- Good: *"200k+ rows on a 16GB box. SQLite-backed."*

**Casual lowercase in code voice, capitalized in customer voice.** README and CLI help use sentence-style normal capitalization. In-source comments lowercase prose ("returns the row count").

**Words to avoid:** *enterprise-grade, mission-critical, AI-powered, blockchain, revolutionize, paradigm, leverage, synergy, robust, seamless.*

**Words to use:** *real, honest, free, local, fast, captured, finding, repeater, intercept, scope, payload.*

## Page templates

### Marketing landing
1. Sticky top nav (brand left, links + CTA right)
2. Hero (52px gradient headline, 17-19px tagline, 2-3 CTAs centered)
3. Feature grid (3-4 column, 240px min cards)
4. Comparison table (vs Burp / mitmproxy)
5. Quickstart code block
6. Roadmap (bullets)
7. Footer (license / privacy / terms / GitHub)

### Pricing
1. Top nav
2. Hero-mini (42px headline)
3. Matrix table (4 columns, feature rows, ✓ / — / capped)
4. CTA row (4 buttons)
5. Notes (refund, fair use, etc.)
6. Footer

### Docs page
1. Top nav with brand / breadcrumb
2. h1 + lead paragraph
3. Long-form content with h2/h3, code blocks, tables, details disclosure
4. Cross-links to other docs pages
5. Footer

## Build your own page in 10 minutes

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>YOUR PAGE -- Nullock</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg" />
<link rel="stylesheet" href="docs/docs.css" />
</head>
<body>
<nav class="topnav">
  <div class="brand"><a href="./">Nullock</a></div>
  <div class="links">
    <a href="docs/">Docs</a>
    <a href="pricing.html">Pricing</a>
  </div>
</nav>
<main>
  <h1>Your headline</h1>
  <p class="lead">Your subhead.</p>
  <!-- content -->
</main>
<footer>
  <a href="LICENSE.html">License</a> ·
  <a href="PRIVACY.html">Privacy</a> ·
  <a href="https://github.com/Bikebrainz/Nullock">GitHub</a>
</footer>
</body>
</html>
```

Drop into `docs/` and it just works.

## Mascot / brand mark

Current: stylized "n" with a lock keyhole in the favicon SVG. Should be redrawn by a real designer when budget allows; the SVG works as a placeholder.

ASCII signature for terminals / commits:
```
       _ _            _
 _ __ | | | ___   ___| | __
| '_ \| | |/ _ \ / __| |/ /
| | | | | | (_) | (__|   <
|_| |_|_|_|\___/ \___|_|\_\
```
