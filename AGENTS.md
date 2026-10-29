# AGENTS.md

Rules for anyone changing this repo, people and coding agents alike.

- A library for apps: the standard library, golang.org/x/sync and go-jose (and `oidcrp` for oauthrs) only. Never import an app.
- Spec-correct first: cite the RFC or OpenID section a behavior comes from, in tests.
- Exported API is additive; a breaking change needs a new major version.
- Gates: `go test -race ./...` and `golangci-lint run`, the same as CI.
- Comments: none by default; exported symbols get a one-sentence doc; keep only markers (`TODO`, `NOTE`, `SECURITY`) or links.
- Conventional Commits, one line; every commit is signed.
- No AI attribution in commits, PRs or files.
- Never weaken a lint or check to get green.
- Never reference untracked files or IDs defined only in them.
