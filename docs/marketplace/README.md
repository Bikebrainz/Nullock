# Nullock Extensions Marketplace -- static site

Single-page directory of vetted extensions. Pure static; no build step.

## Deploy to GitHub Pages

1. In the repo's **Settings -> Pages**, pick **branch: Nullock** /  **folder: /docs**.
2. The marketplace lands at `https://<owner>.github.io/Nullock/marketplace/`.
3. Updating `extensions/marketplace.json` (root) auto-rolls to
   `docs/marketplace/marketplace.json` -- this README's sister CI step is
   the one-liner:
   ```yaml
   - run: cp extensions/marketplace.json docs/marketplace/marketplace.json
   ```
   (manual today; flip to a CI step when v1.0 ships).

## Deploy anywhere else

Drop the contents of `docs/marketplace/` into any static host:
- Cloudflare Pages
- Netlify
- S3 + CloudFront
- A bare nginx server

## Local preview

```sh
python3 -m http.server -d docs/marketplace 8000
# then browse http://localhost:8000/
```

## Adding an extension

Submit a PR to the root `extensions/marketplace.json`. Each entry needs:

```json
{
  "id":         "<unique-slug>",
  "name":       "Human Readable Name",
  "summary":    "One sentence.",
  "version":    "0.1.0",
  "author":     "<your github handle>",
  "categories": ["<tag>", "<tag>"],
  "url":        "https://raw.githubusercontent.com/<your>/<repo>/<ref>/<path>.js",
  "hooks":      ["nullock.onRequest", "..."],
  "config":     { "<key>": { "type": "string", "desc": "..." } }
}
```

The `url` can point at any HTTPS-served JS file -- typically a raw
GitHub URL pinned to a tag, not a branch.
