## What does this PR change?

<!-- 1–3 sentences. If it fixes an issue, write "Fixes #123". -->

## Checklist

- [ ] Title follows Conventional Commits (`feat: …`, `fix: …`, `docs: …`, …) — it feeds the release notes
- [ ] Branch is named `type/slug` (e.g. `fix/hpack-overflow`)
- [ ] `npm run typecheck && npm run lint && npm test` passes locally
- [ ] Behavior changes come with tests (CI enforces the coverage gate)
- [ ] README / docs updated if public behavior changed
- [ ] `package.json` version bumped (patch) — **only for changes to published code; docs/tests/CI-only PRs skip this**

New to the project? You don't need all of this perfect — maintainers will help. Full guide: [browsersmith/CONTRIBUTING.md](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md).

## AI-assisted contribution?

If AI tooling helped write this, a one-line note is enough — it's welcome and doesn't change the review.
