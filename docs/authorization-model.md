# The authorization model

This is the deep reference for the relation-tuple engine that backs the
workspaces service. It explains the tuple format, every built-in namespace and
its rewrite rules, how `Check` evaluates transitively, how to add a namespace,
and how the three motivating products map onto the model. The source of truth
for the API is [`proto/workspace/v1/workspace.proto`](../proto/workspace/v1/workspace.proto)
(proto package `workspace.v1`); the source of truth for the built-in model is
[`pkg/authz/model.go`](../pkg/authz/model.go).

The engine is Zanzibar-inspired: a uniform store of relation tuples plus
per-namespace userset-rewrite rules (see
[ADR-0001](adr/0001-relation-tuples-as-the-authz-primitive.md)).

## Calling the engine

This is an **internal** service, called service-to-service by trusted product
backends — never directly by a browser or mobile client. Every RPC is an HTTP
`POST` over the Connect protocol (JSON, with gRPC and gRPC-Web also supported)
at `/workspace.v1.<Service>/<Method>`. The caller authenticates as a **service**
with a shared bearer credential (`Authorization: Bearer <service-token>`, drawn
from `GATEWAY_SERVICE_AUTH_TOKENS`); a missing or wrong credential returns HTTP
`401` / Connect code `Unauthenticated`.

As in Zanzibar, the **end user is data, not the caller**. End-user
authentication happens at the product edge, before this service is called. The
relevant user is an explicit request field: management RPCs take a required
`acting_user_id` (the user the action is authorized as; omitting it returns
`InvalidArgument`), and `Check` takes a `subject_user_id` (the user being
tested). `project_id` is optional and defaults to `GATEWAY_DEFAULT_PROJECT_ID`.

```bash
# Write a tuple: grant bob admin on workspace acme.
curl -X POST http://localhost:8080/workspace.v1.AuthzService/WriteRelationTuples \
  -H "Authorization: Bearer $WS_SERVICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"updates":[{"op":"OP_INSERT","tuple":{"namespace":"workspace","object_id":"acme","relation":"admin","subject":{"user_id":"bob"}}}]}'

# Check the decision. admin ⊃ member, so this returns allowed.
curl -X POST http://localhost:8080/workspace.v1.AuthzService/Check \
  -H "Authorization: Bearer $WS_SERVICE_TOKEN" -H "Content-Type: application/json" \
  -d '{"namespace":"workspace","object_id":"acme","relation":"member","subject_user_id":"bob"}'
# => {"allowed": true}
```

## The tuple format

A relation tuple is:

```
namespace:object_id#relation@subject
```

- **namespace** — the kind of object (`workspace`, `group`, `resource`, or a
  product's own namespace).
- **object_id** — the specific object.
- **relation** — the relationship being granted (`owner`, `member`, `viewer`, …).
- **subject** — the right-hand side. Exactly one of:
  - a **concrete user** (`user_id`), written `@user:alice` here; or
  - a **userset** — another `namespace:object_id#relation`, meaning "every
    subject that has *that* relation on *that* object". Written
    `@workspace:acme#member`.

Every tuple is scoped to a **`project_id`** (the isolation shard, identity
ADR-0002); it is the leading key of the store. Tuples in different projects
never see each other.

In the proto these are `RelationTuple`, `Subject` (a `oneof` of `user_id` /
`SubjectSet`), and `SubjectSet` (`namespace` / `object_id` / `relation`). In Go
(`pkg/authz`) the same shapes are `Subject` and `SubjectSet`.

## Rewrite rules

A **namespace** maps each relation to a **`Rewrite`** — how to compute the set
of subjects that hold that relation. A `Rewrite` is a union of these primitives
(`pkg/authz/model.go`):

- **`this`** — the relation's own directly stored tuples. A zero `Rewrite` (all
  fields empty) means `this`. This is the leaf.
- **`computed(rel)`** (computed_userset) — evaluate another relation `rel` on
  the **same** object. Used for role hierarchies: `admin` includes `owner`.
- **`tupleToUserset(tupleset, computedRel)`** — for every userset stored under
  relation `tupleset` on this object, evaluate `computedRel` on the referenced
  object. This is how an object **inherits** access from a related object (e.g. a
  resource from its parent workspace).
- **`union(...)`** — grant access if **any** child rewrite does.

Unknown namespaces and unknown relations default to `this` — so a product can
store ad-hoc relations without first registering a namespace; they simply behave
as plain stored tuples with no inheritance.

## Conditions (caveats)

A stored grant may carry an **optional, fail-closed condition** — set
`condition_name` (+ static `condition_params`) on a `RelationTuple`. The grant
then applies only if the named built-in condition evaluates true against the
static params and the request-time `CheckRequest.context`. An unset condition is
unconditional (the default); an unknown name, a missing input, or an ill-typed
value all **deny** (fail closed). The condition is grant metadata, not part of
tuple identity, so re-writing a tuple replaces (or clears) its condition.

This is the single attribute-aware mechanism behind COPPA parental consent,
kids age-gating, scoped integration delegation, and time/IP-bound shares.
Built-ins (`pkg/authz/conditions.go`):

- **`consent_granted`** — `context["consent"]` must be boolean true.
- **`age_at_least`** — `context["age"]` ≥ `params["min_age"]`.
- **`ip_in_cidrs`** — `context["ip"]` is within any of `params["cidrs"]`.
- **`not_after`** — `context["now"]` (RFC3339) is not past `params["until"]`.

Per-project condition definitions and a richer expression evaluator (e.g. CEL)
are tracked follow-ups; today the registry is a fixed pinned set.

## The built-in namespaces

Transcribed from `DefaultModel()` in `pkg/authz/model.go`.

### `workspace`

The membership grades, ordered **owner ⊃ admin ⊃ member ⊃ guest**. Each grade
unions its own direct tuples with the grade above, so an owner is implicitly an
admin, a member, and a guest.

```
owner  := this()
admin  := union(this(), computed("owner"))
member := union(this(), computed("admin"))
guest  := union(this(), computed("member"))
```

`Role` in the proto maps 1:1 onto these relations.
`WorkspaceService.AddMember` etc. write `workspace:<id>#<role>@user:<id>` tuples.

### `group`

A nestable membership set (see
[ADR-0003](adr/0003-groups-separate-from-workspaces.md)).

```
member := this()
```

Just stored tuples — but because a subject may be a userset, a group member can
be another group: `group:all-eng#member@group:backend#member`. `Check` resolves
the nesting transitively.

### `resource`

A generic product object that **inherits** access from its parent — which may
be a workspace **or another resource** (nested folders/collections) — and also
supports **direct** per-object sharing.

```
parent := this()
owner  := this()
editor := union(this(), computed("owner"),
                tupleToUserset("parent", "admin"), tupleToUserset("parent", "editor"))
viewer := union(this(), computed("editor"),
                tupleToUserset("parent", "member"), tupleToUserset("parent", "viewer"))
```

Reading the rules:

- **`parent`** holds tuples like `resource:doc1#parent@workspace:acme#…` (the
  workspace the resource lives in) **or** `resource:doc1#parent@resource:folderB#…`
  (a containing folder). (For a directly-shared resource with no parent,
  `parent` is simply empty.)
- **`editor`** = directly granted editors ∪ the resource's `owner` ∪ **every
  admin of a parent workspace** ∪ **every editor of a parent resource**.
- **`viewer`** = directly granted viewers ∪ everyone who is an `editor` ∪
  **every member of a parent workspace** ∪ **every viewer of a parent resource**.

Each parent kind matches only its own leg: a workspace parent has no
`editor`/`viewer` relation (so those legs grant nothing) and a resource parent
has no `admin`/`member` relation (so those legs grant nothing). A
`resource→resource` chain therefore inherits level by level — `editor` on
`folderA` flows to a `doc` nested two folders deep — bounded by the engine's
`maxDepth` cycle/runaway guard.

So workspace admins can edit anything in the workspace and members can view it,
with **zero** per-resource tuples — while individual users or groups can still be
granted `editor`/`viewer` directly on a single resource.

## How `Check` evaluates

`Check(namespace, object_id, relation, subject_user_id)` answers a boolean:
does this **concrete user** hold this relation on this object? It evaluates the
relation's rewrite rule **transitively**:

1. Look up the rewrite for `(namespace, relation)`.
2. For a **`this`** leaf — is there a stored tuple
   `namespace:object_id#relation@user:<subject>`? If a stored tuple's subject is
   itself a **userset** `ns2:obj2#rel2`, recurse: `Check(ns2, obj2, rel2,
   subject)`. This is what resolves group membership and userset grants.
3. For **`computed(rel)`** — recurse into `Check(namespace, object_id, rel,
   subject)` on the same object.
4. For **`tupleToUserset(tupleset, computedRel)`** — read every userset stored
   under `tupleset` on this object (e.g. each `parent` tuple), and for each
   referenced object recurse into `Check(thatNamespace, thatObject,
   computedRel, subject)`.
5. For a **`union`** — true if any child is true.

Traversal must carry a visited-set / depth bound so cyclic group nesting cannot
loop (see ADR-0003).

`Expand(namespace, object_id, relation)` is the set-valued sibling: instead of
testing one user, it returns the effective **`UsersetTree`** — `UNION` nodes
with child subtrees, and `LEAF` nodes carrying concrete `user_ids` and nested
`sets`. Use it to answer "who has access?" and for audit.

`ReadRelationTuples` is **not** a permission check — it returns raw stored
tuples matching an exact filter, with no rewrite evaluation. Use `Check` for
decisions.

## Adding a new namespace

A consuming product can use the engine in two ways:

1. **Ad-hoc, no registration.** Just write tuples under a new namespace. Unknown
   namespaces/relations default to `this`, so the relations behave as plain
   stored grants with no inheritance. Good for simple direct-sharing models.

2. **With rewrite rules.** To get inheritance, hierarchy, or group expansion,
   add a `Namespace` to the model in `pkg/authz/model.go` (or the product's own
   registration), mapping each relation to a `Rewrite` built from `this()`,
   `union()`, `computed()`, and `tupleToUserset()`. Mirror the `resource`
   namespace: pick a `tupleset` relation that points at the parent object, then
   `tupleToUserset(parent, relationOnParent)` to inherit. Keep grades ordered
   with `computed()` as `workspace` does.

Design checklist for a new namespace:

- Which relations are **directly grantable** (`this`)?
- Which are **implied** by a stronger relation on the same object (`computed`)?
- Does the object **inherit** from a parent — and via which relation on the
  parent (`tupleToUserset`)?
- Will subjects ever be **groups/usersets**? (They always may — the subject side
  is uniform.)

## Worked product mappings

### 1. Workplace collaboration tool (Slack + email + Linear + HR + incident.io)

- **The company** → a `TEAM` `workspace`. Employees are members:
  `workspace:acme#member@user:alice`, `workspace:acme#admin@user:eng-lead`.
- **A Linear-style issue** → a `resource` parented to the workspace:
  `resource:issue-42#parent@workspace:acme`, `resource:issue-42#owner@user:alice`.
  Any acme member can view it and any acme admin can edit it by inheritance.
- **An email distribution / on-call list** → a `group`:
  `group:sre#member@user:bob`. Grant it to an incident in one tuple:
  `resource:incident-7#editor@group:sre#member`.
- **Decision** → `Check(resource, issue-42, viewer, bob)`.

### 2. Learning platform (B2C learners + companies)

- **A company buying seats** → a `TEAM` `workspace`; each seat-holder is a
  `member`.
- **A course** → a `resource` parented to the company workspace:
  `resource:course-go#parent@workspace:bigco`. Every seat-holder is a `viewer`
  by inheritance — no per-learner tuple.
- **A B2C learner buying one course** → works in their `PERSONAL` workspace; the
  course is shared **directly**: `resource:course-go#viewer@user:jo`.
- **Cohorts / TA groups** → `group`s granted `viewer`/`editor` on the course.

### 3. Personal-assistant app (end users sharing tasks)

- **Each user** → a `PERSONAL` `workspace`, auto-provisioned (see
  [ADR-0002](adr/0002-personal-and-team-workspaces.md)).
- **A shared task** → a `resource` shared **directly** (no parent workspace —
  pure `this` leaf): `resource:task-buy-milk#owner@user:parent`,
  `resource:task-buy-milk#editor@user:teen`.
- **A reusable "family" list** → a standalone (project-level) `group`:
  `resource:task-buy-milk#viewer@group:family#member`. The same group is reused
  across every shared task.
- **Decision** → `Check(resource, task-buy-milk, editor, teen)`.
