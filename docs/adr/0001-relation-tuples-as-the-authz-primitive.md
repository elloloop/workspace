# ADR-0001 — Relation tuples as the authorization primitive

## Status

Accepted (2026-06-15).

Foundational ADR for this service. It is the premise the other workspace ADRs
(0002–0003) build on: workspaces, groups, and resource sharing are all
expressed as relation tuples over the engine this ADR adopts.

## Context

Identity [ADR-0001](https://github.com/elloloop/identity/blob/main/docs/adr/0001-two-service-split-identity-vs-workspace.md)
drew a hard line: identity owns authentication and tenancy; a separate service
owns workspaces and fine-grained authorization. This is that service, and it
has to answer one question well, for many different products: **"may this user
do this thing to this object?"**

The products that depend on it do not share an access model:

1. A **workplace collaboration tool** (Slack + email + Linear + HR +
   incident.io) needs company-wide membership, per-issue ownership, on-call
   groups, and resources that inherit access from the team they live in.
2. A **learning platform** serves both B2C learners who buy a single course and
   companies who buy seats that grant a whole roster access to a course.
3. A **personal-assistant app** lets end users share individual tasks with
   specific other people, with no enclosing organisation at all.

The obvious path is a per-product RBAC schema: a `workspace_members` table, a
`course_enrollments` table, an `issue_shares` table, a `task_collaborators`
table, each with its own role columns and its own join logic. That path does
not scale across products. Every new sharing shape is a new table and a new
bespoke query; "does access inherit from the parent?" and "can a group be
granted access?" get re-implemented, inconsistently, in every one of them.
Nested groups and userset-style grants ("everyone who can edit the workspace
can edit this") are especially painful to bolt onto flat membership tables.

Google's Zanzibar describes the alternative: a single, uniform store of
**relation tuples** plus per-namespace **userset-rewrite rules**, against which
every product expresses its model.

## Decision

Adopt **Zanzibar-style relation tuples as the single authorization primitive**.

1. **One store, one shape.** Every grant is a tuple
   `namespace:object_id#relation@subject`, where the subject is a concrete user
   *or* a userset `namespace:object_id#relation`. There are no per-product
   permission tables; there is one tuple store, scoped by `project_id`.

2. **Namespaces carry rewrite rules.** A namespace maps each relation to a
   userset-rewrite expression — a union of `this` (stored tuples),
   `computed_userset` (another relation on the same object), and
   `tuple_to_userset` (walk a relation to related objects, check a relation
   there). Role hierarchies, inheritance from a parent, and group nesting are
   all expressed in these rules rather than in code
   (`pkg/authz/model.go`).

3. **Four generic RPCs.** `AuthzService` exposes `WriteRelationTuples`,
   `ReadRelationTuples` (raw store read, no rewrites), `Check` (transitive
   decision), and `Expand` (effective userset tree). Products talk to these;
   they do not get a bespoke endpoint per access shape.

4. **The engine is generic; the built-ins are defaults.** This service ships
   `workspace`, `group`, and `resource` namespaces to back its own product
   surface, but the engine is namespace-agnostic. Consuming products write
   tuples under their own namespaces, and unknown relations default to the
   `this` leaf so a product can store ad-hoc relations without first
   registering a namespace.

## Consequences

- **Positive.** One model serves every product. A shared task (a `resource`
  direct tuple), a Linear issue (a `resource` with a parent workspace), a
  seat-based course (parent-workspace inheritance), an email group (the `group`
  namespace), a company (a team `workspace`) — all are tuples over the same
  engine, checked by the same `Check`.
- **Positive.** Inheritance and group-based grants are declarative. "Workspace
  admins can edit any resource in it" is one `tuple_to_userset` rule, not a join
  re-written in four products.
- **Positive.** `Check`/`Expand` give uniform decision and audit surfaces;
  "who can view this?" is answerable for any object in any namespace.
- **Negative / learning curve.** Relation tuples and userset rewrites are less
  immediately legible than a `role` column. Contributors must learn the model;
  [`docs/authorization-model.md`](../authorization-model.md) exists to flatten
  that curve.
- **Negative / evaluation cost.** A `Check` may walk computed and
  tuple-to-userset edges transitively, which is more work than a single indexed
  membership lookup. This is the accepted cost of a uniform model; the store is
  indexed on `(project_id, namespace, object_id, relation)` to bound it, and
  hot decisions can be cached on the effective userset.
- **Follow-up.** Zanzibar's consistency tokens (`zookies`) and a per-namespace
  schema-registration API are deliberately out of scope for the first cut;
  decisions are read-your-writes against the primary store.
