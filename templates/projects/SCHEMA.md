# Project template schema

Project templates are JSON files that pre-populate a fresh project's
metadata. Drop new templates into this directory and they'll show up
in `GET /api/project/templates`.

## Shape

```json
{
  "id":          "unique-slug",
  "name":        "Human readable name",
  "description": "One sentence",
  "inScope":     ["host1", "*.host2"],
  "outOfScope":  ["host3"],
  "notes":       "Free-form markdown shown in the project notes pane",
  "rules":       [...],   // MatchReplaceRule[] -- see project_store.cpp
  "sessionRules":[...],   // SessionRule[]      -- see session_rules.hpp
  "extensionsEnabled": ["aws_sigv4.js"]
}
```

## Built-in templates

| ID | Use case |
|---|---|
| `web-app-pentest` | Standard webapp engagement |
| `api-pentest`     | REST / GraphQL API |
| `oauth-review`    | OAuth / SSO flow review |
| `cloud-pentest`   | AWS / GCP / Azure |

## Adding your own

Drop a JSON file into `templates/projects/`. The template appears in
the New Project dialog and in `nullock project templates`.

PRs welcome -- well-curated templates make the "first 5 minutes"
experience much better for newcomers.
