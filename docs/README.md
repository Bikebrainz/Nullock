# Nullock documentation

## Guides

- [Install and build](guides/INSTALL.md)
- [Feature reference](guides/FEATURES.md)
- [Extensions API](guides/EXTENSIONS.md)
- [Intruder project workspaces](guides/INTRUDER_WORKSPACE.md)
- [Deploy an OAST server](guides/DEPLOY_OAST.md)
- [Deploy a workspace server](guides/DEPLOY_WORKSPACE.md)
- [Release signing](guides/RELEASE_SIGNING.md)
- [UI navigation](guides/UI-NAVIGABILITY.md)
- [Packaging](../packaging/README.md)

## Development

- [Contributing and source layout](../CONTRIBUTING.md)
- [Maintenance tools and validation commands](../scripts/README.md)
- [Design documents](design/README.md)
- [Engineering reviews](reviews/README.md)
- [CLI examples](../examples/README.md)
- [Teaching labs](../labs/README.md)
- [Project template schema](../templates/projects/SCHEMA.md)
- [Security model and reporting](../SECURITY.md)
- [Changelog](../CHANGELOG.md)

## Directory conventions

The repository root holds the project overview, contribution and policy files,
and build entry points. Put usage and deployment guides in `docs/guides/`,
architecture proposals in `docs/design/`, and dated reviews in `docs/reviews/`.

This directory also contains the GitHub Pages website: `index.html` is its landing
page, `docs/index.html` is the web documentation portal, and `labs/`, `marketplace/`,
and `roadmap/` contain generated catalogs. Their URLs depend on this layout.
Update generated pages through the corresponding `scripts/*_site.py` or
`scripts/parity_report.py` generator; see the checks in
[CI](../.github/workflows/ci.yml).

Application sources belong in `Src/`, browser application assets in `ui-v2/`,
regression suites in `Tests/`, and maintenance tools in `scripts/`. `bin/nullock`
is the canonical CLI; `scripts/nullock` forwards older invocations to it.
Build output belongs in the ignored `build/` directory.
