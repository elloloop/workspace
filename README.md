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
  expresses its own access model as tuples.
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
**transitively** and answers `allowed`. `Expand(...)` returns the effective
userset tree (the union of leaves and child usersets) for auditing "who has
access". `ReadRelationTuples` is the raw store read — it does **not** evaluate
rewrites; use `Check` for decisions.

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
| `GATEWAY_ADMIN_API_SECRET` | Platform-operator secret for `AdminService` (project config), presented as `X-Admin-Secret`. **Empty disables the admin API** (`Unimplemented`). | — |
| `GATEWAY_POSTGRES_DSN` | Postgres connection string; selects the postgres storage driver | — (memory driver if unset) |
| `GATEWAY_POSTGRES_AUTO_MIGRATE` | Apply pending migrations on boot | `true` |
| `GATEWAY_SERVICE_AUTH_TOKENS` | Accepted service credentials, comma-separated, presented as `Authorization: Bearer <token>`. **Empty disables the requirement** (trust the network/mesh) and logs a warning. | — |
| `GATEWAY_ALLOWED_ORIGINS` | CORS origins for browser callers, comma-separated | — |
| `GATEWAY_HTTP_MAX_BODY_BYTES` | Maximum request body size | `1048576` |
| `GATEWAY_MAX_LIST_OBJECTS` | Maximum candidate objects a single `ListObjects` call scans (over-cap returns `ResourceExhausted`) | `1000` |

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

The binary lives at `cmd/workspace`; `workspace migrate` runs Postgres
migrations explicitly (they also apply on boot when
`GATEWAY_POSTGRES_AUTO_MIGRATE=true`, the default). Health probes are
`GET /healthz` and `GET /readyz`; Prometheus metrics are on `:9090/metrics`.

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
