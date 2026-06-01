# axess documentation source

This folder is the source for the axess book, rendered to HTML by
[mdBook](https://rust-lang.github.io/mdBook/) and published at
<https://gnomesofzurich.github.io/axess/>.

If you landed here on GitHub: the rendered book has search and
sidebar navigation; this folder is the writable source. The table
of contents lives in [`SUMMARY.md`](SUMMARY.md).

## Working on the docs

Local preview with live reload:

```bash
cargo install mdbook
mdbook serve docs/
# open http://localhost:3000
```

The build output (`docs/book/`) is gitignored. GitHub Actions
([`.github/workflows/docs.yml`](https://github.com/GnomesOfZurich/axess/blob/main/.github/workflows/docs.yml))
rebuilds and deploys to GitHub Pages on every push to `main` that
touches `docs/**`.

## Layout

- [`SUMMARY.md`](SUMMARY.md): book table of contents (the canonical
  index)
- [`book.toml`](book.toml): mdBook configuration
- `intro/`, `authentication/`, `authorization/`, `sessions/`,
  `identity/`, `workload-identity/`, `production/`, `project/`,
  `factors/`: chapter source directories grouped by subsystem

The book is organized by subsystem, not by crate. Keep the chapter
taxonomy aligned with the public surface: `authn`, `authz`, session,
identity/device, workload, delegated, production. When code moves, the
book should usually mirror the subsystem boundary rather than the exact
crate path.

Three chapters pull from canonical files at the repo root via
mdBook's `{{#include}}` directive: [`SECURITY.md`](https://github.com/GnomesOfZurich/axess/blob/main/SECURITY.md),
[`OPERATIONS.md`](https://github.com/GnomesOfZurich/axess/blob/main/OPERATIONS.md),
and [`CONTRIBUTING.md`](https://github.com/GnomesOfZurich/axess/blob/main/CONTRIBUTING.md).
Edit those at the repo root; the book picks the changes up on next
build.

## Contributing to the docs

Same workflow as code: branch, edit, open a PR. See
[`CONTRIBUTING.md`](https://github.com/GnomesOfZurich/axess/blob/main/CONTRIBUTING.md)
for the review process. For substantive structural changes, open
an issue first; the book layout is opinionated and PRs that fight
it tend to bounce.
