# Contributing to browsercore-tls

Thanks for your interest in contributing! `@browsercore/tls` is part of the **BrowserCore** family — a browser-identical HTTP/TLS/QUIC stack for TypeScript. This package sits at **layer 2** of the family's dependency graph.

Browser-identical TLS client — fingerprint-accurate ClientHello with JA3/JA4 targets.

> 📖 The **full contribution guide** lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md) — start there for the big picture, the project map, and multi-repo workflows. Everything below gets you started locally in minutes.

## Setup (no linking needed)

Requires **Node ≥ 26** and plain npm (no pnpm/yarn):

```sh
git clone https://github.com/jverneuer/browsercore-tls
cd browsercore-tls
npm install
npm run typecheck && npm run lint && npm test && npm run build
```

All `@browsercore/*` dependencies resolve from npm, so this one repo is all you need for most changes — no workspaces, no `npm link`.

## Reporting an issue

Use the issue templates (**bug report / feature or idea / question**) — fields are mostly optional, and a rough report beats no report. Questions are best asked in the [browsersmith Discussions](https://github.com/jverneuer/browsersmith/discussions). Security issues go through [SECURITY.md](SECURITY.md), never a public issue.

## Making a change

- **Branch:** `type/slug` with lowercase hyphens, e.g. `fix/cookie-domain-match`
- **Commits:** Conventional Commits (`fix: …`, `feat: …`, `docs: …`) — these feed the release notes
- **Tests:** add or adjust tests for behavior changes; CI enforces this repo's coverage gate
- **Version:** docs-only PRs need **no** version bump; code changes bump the patch version in `package.json` (the full guide explains why)

Pull requests run CI automatically (typecheck, lint, tests + coverage, build). Issues and PRs are open to everyone — no CLA, no signing.

Looking for a first task? Check the [`good first issue`](https://github.com/jverneuer/browsercore-tls/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label.
