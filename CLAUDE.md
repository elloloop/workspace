# Project guidance for Claude

The full engineering rules live in [AGENTS.md](./AGENTS.md). They apply
to every change — agent-driven or human. Read them before making any
non-trivial edit.

Highlights for quick recall:

- **No patch fixes.** Change the wrong shape, don't wrap it. No shims,
  no compatibility layers, no translation tables for "old callers."
- **Delete dead code.** When a refactor lands, the old files, types,
  constants, and re-exports go with it.
- **No half-finished implementations.** Land complete features
  (impl + tests + wiring) or split along feature boundaries.
- **Tests are part of the change.** Bug fixes get regression tests.
  Conformance suites get extended, not bypassed.
- **Clean commit messages.** Imperative mood, no AI attribution, no
  references to inaccessible context.
- **PR review gate on every PR.** A multi-agent gate (Triage → Review →
  Verify) via `Workflow({name: 'review-gate', args: <pr-number>})`: five
  always-on reviewers (Product, Security, Performance, Maintainability,
  Correctness) plus a Contract/Migration reviewer when proto/API/schema/
  migration files change and an Accessibility reviewer when UI changes,
  with every blocking finding adversarially re-verified. A maintainer
  step that runs inside the Claude Code harness; advisory (posts a
  comment, never blocks merge), runs alongside CI. Clear its confirmed
  blockers before merging.

If existing code violates these rules and your change touches it, fix
the violation as part of your change. Do not preserve the wrong pattern.

---

## How I expect you to write code

**No shortcuts. "Simple" never means "sloppy."** A small diff that hardcodes,
duplicates, or skips a test isn't simpler — it's deferred cost.

1. **Fix causes, not symptoms.** Find the root cause before fixing. If you're
   applying a workaround, say so explicitly and explain why. Never swallow an
   exception or silence an error to make a problem disappear.

2. **Think about consequences.** Before changing shared or widely-used code,
   trace its callers and the invariants they rely on. A fix that's locally
   correct but breaks something elsewhere — now or later — is not a fix.

3. **SOLID, sensibly.** One responsibility per class/widget/function. Separate
   pure logic from I/O so it can be tested. Inject dependencies that cross a
   boundary so they're mockable. Don't add abstractions for things that don't
   cross a boundary.

4. **DRY about knowledge, not appearance.** Don't duplicate a rule or decision.
   Code that merely looks similar but changes for different reasons stays
   separate. When unsure, prefer duplication over a premature/wrong abstraction.

5. **No hardcoded values.** No magic numbers or strings inline — give them
   names. Environment/tenant/feature-specific values go in typed config in
   application code, never scattered literals, never the database.

6. **Readable & maintainable.** Clear names, short flat functions, early
   returns over deep nesting. Comments explain *why*, not *what*. Match the
   existing style of the file you're editing.

7. **Testable, and prove it.** Ship a test for behavior you add or change. If
   something is hard to test, that's a design smell — restructure until it
   isn't. "Works but can't be tested" means it isn't done.

A change is done only when: the cause (not a symptom) is fixed, no new hardcoded
values, a test covers it, and the analyzer/formatter are clean.

## Project facts

> Keep these current as the repo evolves; only write what you've confirmed.

- **Setup command:** `make install-tools` (pinned golangci-lint + govulncheck); deps via `go mod download`
- **Analyze/lint command:** `make lint` (new-issues vs origin/main) or `make lint-all`; vuln scan `make vuln`
- **Test command (all):** `make test` (`go test -count=1 -race -timeout=1200s ./...`)
- **Test command (single):** `go test -run '^TestName$' ./internal/path/to/pkg`
- **Format command:** `gofumpt` (enforced via golangci-lint `formatters`); run `golangci-lint run --fix` or `gofumpt -w .`
- **Run an app:** `go build ./...` then run `cmd/workspace`; or `docker compose up` (postgres + workspace)
- **Repo layout:** `cmd/workspace` (main), `internal/` (app, config, connect, middleware, service, repo), `pkg/` (authz, jwt), `proto/` + `gen/go` (proto + generated), `workspaceserver/` (mountable server), `tests/` (e2e, integration, conformance harness wiring)
- **What this service is:** the workspace AUTHZ service from `identity`'s ADR-0001 (two-service split). Go + Connect-RPC, Zanzibar-inspired (relation tuples, namespaces, Check/Expand). Every user gets a default personal workspace; users create workspaces and add members (family/team) with roles; it serves B2C and B2B SaaS (the Claude/ChatGPT model). It consumes `identity`'s JWTs and never shares a table with `identity`.
- **State management / data layer conventions:** `internal/repo` drivers (memory, postgres) behind `service.Repository`; all drivers must satisfy `internal/repo/conformance` identically (same uniqueness/ordering/error semantics)
- **Generated files NOT to hand-edit:** `gen/go/**` (buf-generated from `proto/`, regenerate via buf.gen.yaml — pinned plugins)
- **Other gotchas worth recording:** pin every external version exactly (no floating tags — see AGENTS.md §10); config is env-only (`internal/config/config.go`); conformance suite must stay green across all drivers; `go.mod`/`go.sum` must be tidy (`make tidy-check`)
