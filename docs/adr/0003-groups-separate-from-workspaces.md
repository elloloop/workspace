# ADR-0003 — Groups as a distinct nestable namespace, not a workspace sub-type

## Status

Accepted (2026-06-15).

Builds on [ADR-0001](0001-relation-tuples-as-the-authz-primitive.md) (relation
tuples) and [ADR-0002](0002-personal-and-team-workspaces.md) (workspaces). This
ADR decides how reusable membership sets — email lists, chat groups, on-call
rotations — are modelled.

## Context

The motivating products all need named, reusable sets of people that are *not*
tenancy boundaries:

- The **workplace** tool has email distribution lists, chat channels, and
  on-call rotations (`all-engineering`, `sre`, `incident-responders`).
- The **personal-assistant** user has a `family` list they share many different
  tasks with.
- A **learning** company has cohorts and teaching-assistant groups.

These sets share three properties that a workspace does not have:

1. **They are reused across many objects.** `sre` should grant access to dozens
   of incidents and resources without being re-declared each time.
2. **They nest.** `all-engineering` contains `backend` and `frontend`; adding a
   person to `backend` should propagate.
3. **They are not an ownership/billing boundary.** A workspace has one owner and
   is where resources live; a group is just a membership set.

The temptation is to model a group as a special workspace (a "workspace with no
resources") or as a fixed sub-list inside one workspace. Both are wrong: a
workspace is single-owner and tenancy-scoped (ADR-0002), and a group that lives
*inside* one workspace cannot be referenced from another, defeating reuse.

## Decision

Model groups as their own first-class namespace, `group`, distinct from
`workspace`.

1. **`group` is a separate namespace with relation `member`.** Its rewrite rule
   is `this` — a plain stored-tuple set — and a member may itself be a userset,
   so **groups nest**: `group:all-eng#member@group:backend#member`. The
   `GroupService` RPCs (`CreateGroup`, `AddGroupMember`, …) manage it, and a
   `GroupMember` is a `oneof` of a `user_id` or a nested `group_id`.

2. **Granting a group access is one tuple.** Because a tuple's subject can be a
   userset, granting a group access to anything is
   `…#<relation>@group:<id>#member`:

   ```
   workspace:acme#member@group:all-eng#member     # all engineers are acme members
   resource:incident-7#editor@group:sre#member    # on-call can edit the incident
   resource:task-buy-milk#viewer@group:family#member
   ```

   `Check` resolves the group transitively, including nested groups, with no
   special-casing in the consuming product.

3. **Groups are referenceable across workspaces.** A group may be project-level
   (empty `workspace_id` — a B2C user's `family` list) or scoped to a workspace
   (a company's internal groups). Either way it is referenced by id from any
   workspace or resource tuple; scoping is an organisational convenience, not a
   reuse boundary.

## Consequences

- **Positive.** One group, many grants. `sre` is defined once and granted across
  every incident and resource; membership changes propagate everywhere via the
  userset, with no re-grant.
- **Positive.** Nesting is free — it is the same userset mechanism ADR-0001
  already provides; `group` simply allows usersets as members.
- **Positive.** Clean separation of concerns: `workspace` is the
  ownership/tenancy boundary, `group` is the membership set. Neither has to
  pretend to be the other.
- **Negative.** There are now two membership concepts (workspace members and
  group members) and contributors must pick the right one. The rule of thumb:
  if it owns resources and bills, it is a workspace; if it is a named set of
  people you grant access *with*, it is a group.
- **Negative / cycle risk.** Nested groups can in principle form a cycle
  (`a#member@b#member`, `b#member@a#member`). The engine must bound `Check`
  traversal (visited-set / depth limit) so a malformed nesting cannot loop;
  this is an engine-level guard rather than a schema constraint.
