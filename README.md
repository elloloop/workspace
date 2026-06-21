# Workspaces

Internal workspace and authorization microservice. Deploys as a single
container; points at Postgres, exposes Connect-RPC over HTTP/JSON, and is called
**service-to-service** by trusted product backends.

This is the **workspace/authz service** that identity's
[ADR-0001](https://github.com/elloloop/identity/blob/main/docs/adr/0001-two-service-split-identity-vs-workspace.md)
said would be built separately. Identity owns authentication and tenancy and
issues the access token; workspaces owns workspace membership and fine-grained,
ReBAC-style authorization. The two services **never share a table** — the access
token, verified at the **product edge**, is the entire contact point between
them.

> **Docs.** Full guides, concepts, and a live, per-RPC API reference are hosted
> at **<https://elloloop.github.io/workspaces/>**. The Scalar-rendered API
> reference (generated from the proto) is at
> **<https://elloloop.github.io/workspaces/api>**.

## What it provides

- **A relation-tuple authorization engine** (`AuthzService`) — a Zanzibar-style
  ReBAC core. Write tuples, then ask `Check` "may this user do this?" and
  `Expand` "who can?". Generic over namespaces, so any consuming product
  expresses its own access model as tuples. `WriteRelationTuples` returns an
  optional **consistency token**; pass it to a later read
  (`at_least_consistency_token`) for **read-after-write** (observe at least that
  write). See [docs/authorization-model.md](docs/authorization-model.md#consistency-tokens-read-after-write).
- **Workspaces** (`WorkspaceService`) — every user automatically owns one
  **personal** workspace; they may create **team** workspaces and add members
  with a role (`owner` ⊃ `admin` ⊃ `member` ⊃ `guest`). This serves both B2C (a
  personal-assistant user sharing tasks with relatives) and B2B SaaS (a
  company's employees collaborating), the way Claude and ChatGPT model personal
  vs. team plans.
- **Groups** (`GroupService`) — reusable, nestable membership sets (an email
  distribution list, a chat group, an on-call rotation), separate from
  workspaces and referenceable from many of them.
- **Invitations** — token-based invites to a workspace at a given role,
  delivered out of band and redeemed by the invitee.

Workspaces authorizes; it does not authenticate. End users are authenticated at
the product edge — this service never sees or verifies an end-user token.

## The authorization model

The core is a **relation-tuple store**. A tuple reads:

```
namespace:object_id#relation@subject
```

where the **subject** is either a concrete user (`user_id`) or a **userset** —
another `namespace:object_id#relation`, i.e. "everyone who has `relation` on
that object". For example:

```
workspace:acme#member@user:alice          # alice is a member of workspace acme
workspace:acme#member@group:all-eng#member # every member of group all-eng is a member of acme
resource:doc1#viewer@user:bob              # doc1 is shared with bob directly
```

Each **namespace** maps every relation to a **userset-rewrite rule** — a union
of three primitives:

- **this** — the relation's own directly stored tuples.
- **computed_userset** — another relation on the *same* object (this is how
  `owner` grants `admin` grants `member`).
- **tuple_to_userset** — walk a relation on this object to *related* objects,
  then check a relation there (this is how a resource inherits access from its
  parent workspace).

`Check(namespace, object, relation, subject_user_id)` evaluates that rule
**transitively** and answers `allowed`. The subject may instead be a **userset**
— pass `subject_set` (e.g. `group:cohort-7#member`) instead of `subject_user_id`
to ask "does this group/service-account set have the relation?"; the answer is
true when the set is structurally included or any of its concrete members has
the relation. `Expand(...)` returns the effective userset tree (the union of
leaves and child usersets) for auditing "who has access". `ReadRelationTuples`
is the raw store read — it does **not** evaluate rewrites; use `Check` for
decisions.

The built-in namespaces (`pkg/authz/model.go`):

| Namespace | Relations | Rewrite shape |
|---|---|---|
| `workspace` | `owner`, `admin`, `member`, `guest` | each grade includes the one above it (`admin` = this ∪ `owner`, `member` = this ∪ `admin`, …) |
| `group` | `member` | `this` only — subjects may themselves be group usersets, so groups nest |
| `resource` | `parent`, `owner`, `editor`, `viewer` | `editor` = this ∪ `owner` ∪ (parent workspace's `admin`); `viewer` = this ∪ `editor` ∪ (parent workspace's `member`) |

See [`docs/authorization-model.md`](docs/authorization-model.md) for the full
reference. Three motivating products, each mapped onto the model:

### Worked example — a workplace collaboration tool

A Slack-plus-Linear-plus-incident.io workplace app. The company is a **team
workspace**; an internal Linear-style issue is a `resource` whose `parent` is
that workspace.

```
workspace:acme#owner@user:ceo
workspace:acme#member@user:alice
resource:issue-42#parent@workspace:acme       # issue-42 lives in acme
resource:issue-42#owner@user:alice            # alice filed it
```

`Check(resource, issue-42, viewer, bob)` where bob is an `acme` member: the
`viewer` rule's `tuple_to_userset("parent", "member")` walks `issue-42`'s
parent to `workspace:acme`, checks `member` there, and returns **allowed** —
without ever writing a per-issue tuple for bob. An on-call group gets edit
access in one tuple: `resource:incident-7#editor@group:sre#member`.

### Worked example — a learning platform

B2C learners and companies buying seats. A company is a **team workspace**; a
course is a `resource` parented to it, so every seat-holder is a `viewer` by
inheritance. A B2C learner works in their **personal workspace**; a course they
buy is shared directly:

```
resource:course-go#parent@workspace:bigco     # bigco's seats can view it
resource:course-go#viewer@user:individual-jo  # jo bought it personally
```

### Worked example — a personal-assistant app

End users share tasks with other people. Each user lives in their **personal
workspace**; a shared task is a `resource` shared **directly** (no parent
workspace), which is exactly the `this` leaf of the `viewer`/`editor` rules:

```
resource:task-buy-milk#owner@user:parent
resource:task-buy-milk#editor@user:teen        # shared with a family member
resource:task-buy-milk#viewer@group:family#member
```

`group:family` is a standalone group the user maintains and reuses across many
tasks.

## Workspaces, groups, and invitations

`WorkspaceService` is the product surface over the `workspace` namespace.

- **Personal workspace.** `ListWorkspaces` auto-provisions the caller's single
  `PERSONAL` workspace on first call. It is undeletable and admits exactly one
  member — the owner (see [ADR-0002](docs/adr/0002-personal-and-team-workspaces.md)).
- **Team workspaces.** `CreateWorkspace` makes a `TEAM` workspace the acting
  user owns. `AddMember` / `UpdateMemberRole` / `RemoveMember` / `ListMembers`
  manage membership; each membership is mirrored as a `workspace:<id>#<role>`
  tuple, so a `Check` against the workspace namespace honours it immediately.
  `AddMember`, `UpdateMemberRole`, and `CreateInvitation` reject `ROLE_OWNER` —
  ownership is set at creation, not granted.
- **Invitations.** `CreateInvitation` returns a one-time `token` (echoed only
  on creation, never by `ListInvitations`) for out-of-band delivery;
  `AcceptInvitation` redeems it into a membership; `RevokeInvitation` cancels a
  pending one.

`GroupService` manages the `group` namespace — reusable, nestable subject sets
that are deliberately **not** workspaces (a workspace is a tenancy/ownership
boundary; a group is a membership set referenced from many of them). A group
may be project-level (a B2C user's "family" list) or scoped to a workspace (a
company's internal groups), and a group member is either a user or another
group. See [ADR-0003](docs/adr/0003-groups-separate-from-workspaces.md).

A group used as a **cohort/class** can track each member's enrollment lifecycle
(`SetEnrollmentState`/`ListEnrollments`): `enrolled`/`active` place the member in
the group's `#member` set, while `waitlisted`/`completed`/`dropped` record the
state without granting access — access moves purely by tuple presence, atomically.

**Seats / licenses.** `SeatService` counts consumed seats per `(project, tenant,
sku)` and enforces a cap at write time: `SetSeatLimit` configures the cap,
`AssignSeat` grants a seat and fails closed (`ResourceExhausted`) once the cap is
reached — the count-check and insert are one atomic, race-safe operation, so
concurrent assigns can never oversubscribe. A sku with no configured limit is
unlimited; a limit of `0` admits none; `SetSeatLimit` with no `limit` **clears**
the cap (back to unlimited). Lowering a cap below current usage is allowed (a
**downgrade**): it succeeds, `GetSeatUsage` then reports `used > limit`, and
further `AssignSeat` is denied until seats are revoked below the new cap — no
seat is ever auto-revoked. Re-assigning a seated user is idempotent and
**re-asserts** the backing tuple (a seat always grants access). Each assignment
writes a `seat:<sku>#holder@user` tuple — the `seat` namespace is **reserved**
(it cannot be written via `WriteRelationTuples`, only `AssignSeat`/`RevokeSeat`),
so `Check` can gate on seat-holding without the count and access diverging.
`RevokeSeat` frees a seat; `DeprovisionUser` also reclaims a leaving user's seats;
`GetSeatUsage`/`ListSeats` report consumption.

### Calling the API

Every RPC is an HTTP `POST` over the [Connect protocol](https://connectrpc.com)
(JSON, with gRPC and gRPC-Web also supported) at
`/workspace.v1.<Service>/<Method>`. The caller authenticates as a **service**
with a shared bearer credential; the end user is passed as **data**:
management RPCs take a required `acting_user_id` (omitting it returns
`InvalidArgument`), and `Check` takes a `subject_user_id` independent of the
caller. `project_id` is optional and defaults to the configured project.

```bash
# List (and auto-provision) alice's workspaces. acting_user_id is required.
curl -X POST http://localhost:8080/workspace.v1.WorkspaceService/ListWorkspaces \
  -H "Authorization: Bearer $WS_SERVICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"acting_user_id":"alice"}'

# Ask the engine whether bob is an admin of workspace W.
curl -X POST http://localhost:8080/workspace.v1.AuthzService/Check \
  -H "Authorization: Bearer $WS_SERVICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"namespace":"workspace","object_id":"W","relation":"admin","subject_user_id":"bob"}'
```

A missing or wrong service credential returns HTTP `401` / Connect code
`Unauthenticated`.

## How it relates to identity

Per identity
[ADR-0001](https://github.com/elloloop/identity/blob/main/docs/adr/0001-two-service-split-identity-vs-workspace.md),
the AuthN/authz seam is a hard line:

- **identity** owns authentication, the `User` pool, `Project`, `Tenant`,
  `Domain`, and tenant-level membership. It issues the access token.
- **workspaces** (this service) owns workspaces, workspace membership, groups,
  and all fine-grained ReBAC.

The two **never share a table**. End-user authentication happens at the
**product edge**: the product backend verifies the user's identity token, then
calls this service **as itself** over an internal, service-to-service channel.
Like Zanzibar, the end user is **data** here, not the caller — the acting user
and the subject are explicit request fields.

`project_id` is the **isolation shard** (identity
[ADR-0002](https://github.com/elloloop/identity/blob/main/docs/adr/0002-project-the-isolation-shard.md)):
every workspace row, group, invitation, and relation tuple is scoped to it. A
request with no `project_id` falls back to `GATEWAY_DEFAULT_PROJECT_ID`. One
B2C product is typically one project with many users' personal workspaces; a
B2B platform can shard per customer into separate projects.

## Configuration

All config is via environment variables (the `GATEWAY_` prefix matches identity).

| Var | Purpose | Default |
|---|---|---|
| `GATEWAY_CONNECT_PORT` | Connect/HTTP (JSON + gRPC) listen port | `8080` |
| `GATEWAY_METRICS_PORT` | Prometheus metrics listen port | `9090` |
| `GATEWAY_DEFAULT_PROJECT_ID` | Project shard pinned for requests with no `project_id` | `default` |
| `GATEWAY_DEFAULT_TENANT_ID` | Tenant (data-isolation shard within a project) pinned for requests with no `tenant_id` | — (empty = default tenant) |
| `GATEWAY_DATA_REGION` | Data region this instance serves. When set, the service **refuses** (fail-closed, `FailedPrecondition`) to operate on a project whose `data_region` differs — so a mis-routed request never reads/writes data in the wrong region (emits `authz_region_refused_total` + a `data_region_refused` log). Empty = region-agnostic (serves all projects). A project repin converges fleet-wide only after the resolver TTL (~30s); unpin a project via `UpdateProject`'s `clear_data_region`. Multi-region storage **routing** is forward-compat; today this is the recording + validation + serving guard. | — (region-agnostic) |
| `GATEWAY_ADMIN_API_SECRET` | Platform-operator secret for `AdminService` (project config), presented as `X-Admin-Secret`. **Empty disables the admin API** (`Unimplemented`). When set it must be a high-entropy value of **at least 32 characters** (startup fails otherwise). | — |
| `GATEWAY_POSTGRES_DSN` | Postgres connection string; selects the postgres storage driver | — (memory driver if unset) |
| `GATEWAY_POSTGRES_AUTO_MIGRATE` | Run the expand migration on boot. **Opt-in (default `false`):** migrations are a deliberate operator step so a large existing DB's first deploy can never livelock on a bounded `CONCURRENTLY` build inside the boot window. Set `true` only for small/dev DBs. When opted in, a contended migration lock is treated as transient (logs `migrate_lock_contended` WARN and starts without migrating — another actor is migrating); a boot-migrate that exceeds the boot window logs `migrate_boot_timeout` and exits. The recommended prod path is out-of-band `workspace migrate` (expand) then `workspace migrate --contract`. | `false` |
| `GATEWAY_SERVICE_AUTH_TOKENS` | Accepted service credentials, comma-separated, presented as `Authorization: Bearer <token>`. **Empty disables the requirement** (trust the network/mesh) and logs a warning. | — |
| `GATEWAY_SERVICE_CREDENTIALS` | Optional JSON list mapping a credential to a named calling-service identity with an optional project pin: `[{"token":"…","name":"slack","project":"slack-proj"}]`. A mapped credential authenticates **and** carries its identity (recorded as `caller` in audit/decision logs); a pinned credential is **forced into its project** — its requests' `project_id` field is **ignored**, so don't build multi-project logic against one pinned credential. Each token must be ≥32 chars. Additive — flat `GATEWAY_SERVICE_AUTH_TOKENS` still work as anonymous credentials. **Rollback note:** during a rollout, also list each mapped token in `GATEWAY_SERVICE_AUTH_TOKENS` so a revert degrades to an anonymous-but-authenticated caller (HTTP `200`) rather than `401`. | — |
| `GATEWAY_ALLOWED_ORIGINS` | CORS origins for browser callers, comma-separated | — |
| `GATEWAY_HTTP_MAX_BODY_BYTES` | Maximum request body size | `1048576` |
| `GATEWAY_MAX_LIST_OBJECTS` | Maximum candidate objects a single `ListObjects` call scans (over-cap returns `ResourceExhausted`). Also sizes the fan-out read budget (see `GATEWAY_MAX_CHECK_READS`), so tune the two together. | `1000` |
| `GATEWAY_MAX_EXPAND_NODES` | Maximum nodes/subjects in a single `Expand` result tree (over-cap returns `ResourceExhausted`). Also sizes the `Expand` fan-out read budget (see `GATEWAY_MAX_CHECK_READS`), so tune the two together. | `10000` |
| `GATEWAY_MAX_BATCH_CHECK_ITEMS` | Maximum items in a single `BatchCheck` request | `1000` |
| `GATEWAY_MAX_CHECK_READS` | Per-request store-read budget: the max tuple lookups one `Check`/`CheckSet`/`Expand`/`ListObjects` evaluation may perform. Bounds worst-case per-request cost when a tenant plants a deep/branching/cyclic model graph; exhausting it returns `ResourceExhausted` (an error, not a silent deny, so an abusive query stays visible) and increments `authz_eval_backstop_total{reason="budget"}`. This flat value is the budget for a SINGLE `Check`. A FAN-OUT operation SCALES the budget off the cap that already bounds it (never tighter than that cap × headroom): `ListObjects`/`CheckSet` use `max(GATEWAY_MAX_CHECK_READS, GATEWAY_MAX_LIST_OBJECTS × maxDepth(32) × 2)`; `Expand` uses `max(GATEWAY_MAX_CHECK_READS, GATEWAY_MAX_EXPAND_NODES × 2)` (its read cost tracks reachable usersets ≈ nodes, and the node cap stays the primary bound) — so a legitimate full-cap scan/expand returns the correct result while an all-cyclic graph still trips. Size `GATEWAY_MAX_CHECK_READS` to the deepest/widest real tenant model and tune it together with `GATEWAY_MAX_LIST_OBJECTS`/`GATEWAY_MAX_EXPAND_NODES`; a pathologically wide union/`tupleToUserset` model could still need a higher knob than the scaled budgets provide. Alert on `authz_eval_backstop_total{reason="budget"}` from day one. Generous default — legitimate deep folder/group hierarchies read far fewer tuples. `0` or negative = the service default. A small positive value is REJECTED at startup (must be `>= 100`): a typo like `5` would otherwise fail authz closed fleet-wide. | `5000` |
| `GATEWAY_ADMIN_RATE_LIMIT_PER_MINUTE` | Per-caller request cap on the admin API (online brute-force protection); over-limit returns `ResourceExhausted`. `0` or negative disables it. | `30` |
| `GATEWAY_TENANT_RATE_LIMIT_PER_MINUTE` | Per-`(project, tenant)` request cap on the authz data-plane RPCs (Check/BatchCheck/Expand/ListObjects/WriteRelationTuples/…); over-limit returns `ResourceExhausted`. `0` or negative (the default) disables it. | `0` |
| `GATEWAY_DECISION_LOG` | Enable the append-only authorization decision audit log: every `Check`/`CheckSet` decision is emitted to the structured logger by an async, non-blocking drain (full buffer drops + counts; never slows or fails a check). | `false` |
| `GATEWAY_AUDIT_LOG` | Enable the append-only change audit log: every relation-tuple grant/revocation (`WriteRelationTuples`) and admin mutation (`CreateProject`/`UpdateProject`, incl. status/model changes — the admin secret is never logged) is emitted to the structured logger by the same async, non-blocking drain. | `false` |

## Deployment

The repo ships a `docker-compose.yml` that brings up Postgres and the
workspaces service together:

```bash
docker compose up -d --build
curl http://localhost:8080/healthz
docker compose logs -f workspaces
docker compose down -v          # stop and wipe the postgres volume
```

Run standalone against an existing Postgres:

```bash
docker run -p 8080:8080 -p 9090:9090 \
  -e GATEWAY_POSTGRES_DSN='postgres://workspaces:password@db:5432/workspaces?sslmode=disable' \
  -e GATEWAY_DEFAULT_PROJECT_ID=my-product \
  -e GATEWAY_SERVICE_AUTH_TOKENS="$(openssl rand -hex 32)" \
  ghcr.io/elloloop/workspace:latest
```

The binary lives at `cmd/workspace`; schema changes follow a two-phase
**expand / contract** pattern so a tenant primary-key widening never takes a
long `ACCESS EXCLUSIVE` lock on a populated hot-path table:

- **Expand — `workspace migrate`** (also applied on boot when
  `GATEWAY_POSTGRES_AUTO_MIGRATE=true`, which is **opt-in** — the default is
  `false`). Idempotent and safe to run on every boot. It creates/upgrades the schema and, for a database still on the
  old single-column primary key, builds each composite `(project_id, tenant_id,
  …)` key as a `UNIQUE INDEX CONCURRENTLY` (no `ACCESS EXCLUSIVE` lock) while
  **leaving the old primary key intact** — so old and new binaries interoperate
  during a rolling deploy (no `42P10`; writes' `ON CONFLICT` targets the
  composite columns, satisfied by the new index). On a fresh database the
  `CREATE TABLE` installs the composite key directly (instant on an empty table)
  and expand is a no-op. DDL runs on a **dedicated, short-lived connection**
  (never the request-serving pool, so the per-session `lock_timeout` it sets can
  never leak onto a connection that later serves traffic) outside a wrapping
  transaction (required for `CONCURRENTLY`), under a **session-level advisory
  lock** so concurrent replicas serialize. The advisory-lock wait is **bounded**
  (~30s, via `pg_try_advisory_lock` polling): a replica blocked behind a stuck or
  long out-of-band migrator fails fast with `another migration holds the lock;
  retry` rather than hanging forever. On the boot-path (auto-migrate) expand
  this lock-held case is **transient and benign**: it logs `migrate_lock_contended`
  (WARN) and the service **starts without migrating** — the other actor is
  migrating the schema, and an expanded-but-not-contracted schema serves fine, so
  this replica picks up the finished schema once that actor completes. The
  boot-path expand additionally runs under a bounded context; if that deadline is
  exceeded (a too-slow `CONCURRENTLY` build on a large DB) it logs
  `migrate_boot_timeout` (advising `GATEWAY_POSTGRES_AUTO_MIGRATE=false` plus an
  out-of-band migrate) and the process exits. A genuine schema/DDL error is
  always fatal. The stale pre-tenant
  `workspaces_personal_uniq` index is replaced **without a uniqueness gap**: the
  tenant-scoped index is built `CONCURRENTLY` under a temp name first, then the
  old index is dropped and the temp renamed in one short transaction.

  Each phase logs `migrate_start` and `migrate_complete` with
  `phase=expand|contract`. After expand, any table whose primary key is not yet
  composite is reported via a structured **`migrate_contract_pending`** WARN
  listing those tables — a signal that cross-tenant id/tuple reuse is not yet
  enabled and `workspace migrate --contract` is still required. It never fires on
  a fresh (born-composite) database. Alert on it lingering after a deploy.
- **Contract — `workspace migrate --contract`.** A separate, **deliberately
  invoked** step, run **only after the whole fleet is on the new binary**. It
  promotes each composite unique index to the table's `PRIMARY KEY` (via `ADD
  CONSTRAINT … PRIMARY KEY USING INDEX`, which adopts the already-built index
  rather than rebuilding it, so its `ACCESS EXCLUSIVE` lock is brief and
  independent of table size) and drops the old narrow primary key. Idempotent: a
  table already on the composite key is skipped. **Never** run automatically on
  boot. **Cross-tenant id/tuple reuse activates only after contract:** in the
  expand-only window the old narrow PK is still in force, so reusing a logical id
  in a second tenant collides on it; promoting the composite key to the PK is
  what enables the reuse.

Auto-migrate is **off by default**. **On a large, already-populated database**
this is the required posture: boot does not run migrations on the
request-serving path; run `workspace migrate` (expand) out of band, complete the
rolling deploy, then run `workspace migrate --contract` during a maintenance
window. **For a fresh/small or local/dev database**, either run `workspace
migrate` (expand) explicitly or set `GATEWAY_POSTGRES_AUTO_MIGRATE=true` for
convenience (this is what `docker compose up` does, so the dev schema is created
on boot). Health probes are `GET /healthz` and `GET /readyz`; Prometheus metrics
are on `:9090/metrics`, including authorization-decision metrics:
`authz_check_decisions_total{namespace,relation,allowed}` (Check/CheckSet and
per-item BatchCheck outcomes), `authz_check_duration_seconds{rpc}` latency,
`authz_decision_errors_total{rpc}`, and `authz_batchcheck_items` (items per
BatchCheck), plus `authz_eval_backstop_total{reason}` — counts engine
per-request safety backstops that fired, `reason` ∈ `depth`/`cycle` (a graceful
fail-closed deny when recursion is too deep or cyclic) or `budget` (the
per-request read budget was exhausted, a `ResourceExhausted` error). A rising
rate is an alertable signal that an instance is hitting backstops — an abusive
tenant or a misconfigured deep/cyclic model. Labels are deliberately
low-cardinality — no object or subject.

**Runbook — sizing the read budget.** `GATEWAY_MAX_CHECK_READS` must be sized to
the deepest/widest real tenant model and tuned **together** with
`GATEWAY_MAX_LIST_OBJECTS` and `GATEWAY_MAX_EXPAND_NODES`: a fan-out's budget
scales off the cap that already bounds it, NOT the flat
`GATEWAY_MAX_CHECK_READS` — `ListObjects`/`CheckSet` as `GATEWAY_MAX_LIST_OBJECTS
× maxDepth (32) × 2`, `Expand` as `GATEWAY_MAX_EXPAND_NODES × 2` — so a
legitimate full-cap scan/expand is not wrongly denied. A pathologically wide
union/`tupleToUserset` model could still exceed the scaled budgets and need a
higher `GATEWAY_MAX_CHECK_READS` knob. **Alert on
`authz_eval_backstop_total{reason="budget"}` from day one**: a sustained nonzero
rate means a tenant is tripping the budget — if the tenant is legitimate (a valid
but unusually deep/wide hierarchy), raise the caps in step; if abusive, the
`ResourceExhausted` errors are the intended signal. In `BatchCheck`, a budget
trip is isolated to the offending item and does not fail the batch.

The single-`Check` budget is **global** (one value for the whole fleet); there is
no per-project/per-tenant override yet. A read-heavy single-`Check` tenant (an
unusually wide `union`/`tupleToUserset` model) can therefore force the global
ceiling to be raised for everyone — so size to the widest real tenant and treat
the `authz_eval_backstop_total{reason="budget"}` alert as **load-bearing,
provisioned day-one**: it is the only signal distinguishing a legitimate
wide-model tenant (raise the knob) from an abusive one (the errors are intended).
A per-project/per-tenant override is tracked as a follow-up
([#63](https://github.com/elloloop/workspace/issues/63)).

## Storage

Workspaces persists behind a single `service.Repository` interface with two
drivers:

- **memory** — the default when `GATEWAY_POSTGRES_DSN` is unset; for tests and
  zero-dependency local runs. It is also the conformance reference.
- **postgres** — the production driver (pgx); the relation-tuple store,
  workspaces, memberships, groups, and invitations all live here. Every table
  and index leads with `project_id`.

A **conformance suite** asserts both drivers behave identically across every
`Repository` method — same uniqueness, ordering, and error-translation
semantics — so `Check` returns the same answer regardless of backend. Run it
with `make conformance-all`.

## Development

```bash
make ci         # lint, tidy-check, vuln, build, test, smoke, integration, fuzz
make test       # unit tests with the race detector
make proto      # regenerate Go stubs from proto (buf generate)
make openapi    # regenerate the OpenAPI spec that the live API reference reads
```

`make help` lists every target. The proto under
[`proto/workspace/v1/workspace.proto`](proto/workspace/v1/workspace.proto) is
the source of truth for the API; regenerate stubs with `make proto` after
editing it.
</content>
