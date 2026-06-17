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
- **`scope_in`** — `context["scope"]` (the action being performed) is in
  `params["allowed"]` (the scopes this grant authorizes).

Per-project condition definitions and a richer expression evaluator (e.g. CEL)
are tracked follow-ups; today the registry is a fixed pinned set.

## Scoped integration delegation / on-behalf-of

Integrations (Slack, Linear, incident.io, …) act on a workspace's behalf but
should hold **limited, constrained** authority — "Slack may read tasks but not
change membership", "only during business hours", "only before this grant
expires". This is **not a new primitive**: it composes the condition layer above
with the per-credential calling identity (see the README's
`GATEWAY_SERVICE_CREDENTIALS`).

Model the integration as a stable subject (e.g. `user:svc:slack`, or a group)
and give it a grant carrying a condition that the product checks per request:

```jsonc
// Grant: svc:slack may edit doc1, but only for task actions.
RelationTuple{ namespace:"resource", object_id:"doc1", relation:"editor",
  subject: user:"svc:slack",
  condition_name: "scope_in",
  condition_params: { "allowed": ["tasks:read", "tasks:write"] } }
```

On the hot path the product passes what it is doing as `CheckRequest.context`:

```jsonc
Check{ namespace:"resource", object_id:"doc1", relation:"editor",
  subject_user_id:"svc:slack", context: { "scope": "tasks:read" } }   // → allow
Check{ … subject_user_id:"svc:slack", context: { "scope": "membership:write" } } // → deny
```

**One condition per grant.** A grant carries exactly one `condition_name`, so
`scope_in`, `not_after`, and `ip_in_cidrs` cannot be AND-composed on a single
tuple — pick the strictest single condition the grant needs. Two notes:

- For **auto-expiry**, prefer the orthogonal per-tuple `expires_at` field (it
  composes with *any* condition — the tuple stops granting once it lapses,
  evaluated at read time) rather than the `not_after` condition, so you can have
  a `scope_in` grant that also expires.
- **Multiple grants on the same object combine as a UNION (OR)** — more
  permissive, never an AND. Do not model two conditioned grants expecting their
  conditions to both have to hold. Conjunctive (AND-composed) conditions on one
  grant are a tracked follow-up; today, where conjunction is required, express it
  as a single relation built from `intersection` over separately-conditioned
  relations, or pre-combine the predicate into one custom condition.

Because every grant is fail-closed, a request that omits the expected context is
denied. Conditions are evaluated identically on `Check` and `CheckSet` (both
carry request context). **`BatchCheck` does NOT carry request context**, so a
conditional grant is denied through it — use `Check`/`CheckSet` for conditional
(delegated) grants.

**Auditing.** When a credential is mapped to a named principal, that name is the
`Principal.Caller`, and every `Check`/`CheckSet` decision and tuple-change is
recorded with a `caller` field (decision/audit logs), so a delegated action is
attributable to the integration that performed it.

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

#### Enrollment lifecycle overlay (cohorts / classes)

When a group is used as a cohort or class, `GroupService.SetEnrollmentState`
tracks each member's lifecycle state while keeping access driven purely by tuple
presence — the same mechanism as workspace member suspend/reinstate. The state
maps to membership like so:

| State | In `#member` set? |
|---|---|
| `enrolled`, `active` | **yes** — backing `group:<id>#member` tuple present |
| `waitlisted`, `completed`, `dropped` | no — tuple absent, state still recorded |

`SetEnrollmentState` upserts the enrollment row and adds/removes the member tuple
**atomically**, so a `Check`/`CheckSet` over `group:<cohort>#member` (and anything
that inherits from it, e.g. a course resource granted to the cohort) automatically
excludes a completed, dropped, or waitlisted enrollee, and re-includes them on
re-enrollment — with no separate status read on the hot path. `ListEnrollments`
returns the tracked states. The overlay is additive: plain
`AddGroupMember`/`RemoveGroupMember` still work for un-tracked membership.

### Seats / licenses (`SeatService`)

`SeatService` counts consumed seats for a `sku` (plan/entitlement) per
`(project, tenant)` and **enforces a cap at write time**:

- `SetSeatLimit(sku, limit)` configures the cap (`limit >= 0`; `0` admits none).
  A sku with **no** configured limit is **unlimited**; calling `SetSeatLimit`
  with the `limit` field **absent clears** the cap (back to unlimited) — the only
  way to undo a previously-set limit over the wire.
- **Downgrade:** lowering a cap below current usage is **allowed** —
  `SetSeatLimit` succeeds, `GetSeatUsage` then reports `used > limit`, and further
  `AssignSeat` is denied until enough seats are revoked to drop below the new cap.
  Existing assignments are never auto-revoked.
- `AssignSeat(sku, user)` grants a seat. It **fails closed** with
  `ResourceExhausted` once the cap is reached, assigning nothing. The
  count-check and the insert run in **one transaction** (Postgres serializes
  concurrent assigns for a sku with an advisory lock; memory under its mutex),
  so two racing assigns can never both succeed past the cap. Re-assigning an
  already-seated user is **idempotent** (no extra seat) and **re-asserts** the
  backing tuple, so a counted seat always grants access (self-healing).
- Each assignment also writes a `seat:<sku>#holder@user` relation tuple, so a
  product model can gate access on seat-holding (e.g. a course `viewer` rewrite
  that unions in `seat:pro#holder`). The `seat` namespace is **reserved** — these
  tuples can only be minted/removed via `AssignSeat`/`RevokeSeat`, never the
  generic `WriteRelationTuples` (rejected) — so the count and the granted access
  cannot diverge. `RevokeSeat` frees the seat and deletes the tuple, atomically;
  `DeprovisionUser` also reclaims a user's seats project-wide.
- `GetSeatUsage`/`ListSeats` report consumption (`used`, `limit`, `limited`).

### `resource`

A generic product object that **inherits** access from its parent — which may
be a workspace **or another resource** (nested folders/collections) — and also
supports **direct** per-object sharing.

```
parent := this()
owner  := this()
editor := union(this(), computed("owner"), tupleToUserset("parent", "editor"))
viewer := union(this(), computed("editor"), tupleToUserset("parent", "viewer"))
```

This relies on `editor`/`viewer` aliases declared in the `workspace` namespace
(`editor := computed("admin")`, `viewer := computed("member")`), so a single
parent leg handles **both** parent kinds:

- **`parent`** holds tuples like `resource:doc1#parent@workspace:acme#…` (the
  workspace the resource lives in) **or** `resource:doc1#parent@resource:folderB#…`
  (a containing folder). (For a directly-shared resource with no parent,
  `parent` is simply empty.)
- **`editor`** = directly granted editors ∪ the resource's `owner` ∪ the
  **parent's `editor`** — which for a workspace parent resolves to its admins
  (via the alias) and for a resource parent recurses up the folder chain.
- **`viewer`** = directly granted viewers ∪ everyone who is an `editor` ∪ the
  **parent's `viewer`** — workspace members for a workspace parent, the parent
  folder's viewers for a resource parent.

Because the aliases resolve **through the model** (computed), they read no raw
tuples, so a stray `workspace:w#editor@x` tuple is **inert** and cannot leak
onto child resources. A `resource→resource` chain inherits level by level —
`editor` on `folderA` flows to a `doc` nested two folders deep. Deep/branching
hierarchies are bounded two ways: the engine caps recursion at `maxDepth`
(`32`), past which **every** path — `Check`, `Expand`, and `CheckSet` — **fails
closed gracefully** (a clean deny / truncated tree, never an error/`CodeInternal`),
and a **request-scoped memo** collapses the DAG so each node is evaluated once
per call (acyclic results are cached; cyclic models recompute and stay
fail-closed). A tighter per-request read budget and deeper nesting are tracked
follow-ups.

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

## Consistency tokens (read-after-write)

A caller that needs **read-after-write** — to immediately observe a grant it just
wrote — uses an optional, opaque **consistency token** ("zookie"):

- `WriteRelationTuples` returns a `consistency_token` naming the
  `(project, tenant)` shard's monotonic write sequence reached by that batch.
- `Check` / `CheckSet` / `Expand` / `ListObjects` / `BatchCheck` /
  `ReadRelationTuples` accept an optional `at_least_consistency_token`. When set,
  the read must reflect state **at least as fresh** as the token. Empty = read
  latest (unchanged default).
- A malformed token, or one issued for a **different shard**, is rejected with
  `InvalidArgument` — never silently ignored. A token demanding a sequence the
  store has not reached fails closed with `FailedPrecondition`.

**What it guarantees today vs. tomorrow.** This is a single primary store, so a
read already sees every committed write — any token the store issued is satisfied
immediately, and the token's value today is a **strict client contract** plus
**forward-compatibility**: the plumbing and monotonic semantics are in place so
that when read replicas are added, a replica lagging behind a token will wait-for
or route-to-primary rather than serve a stale read. It is **not** a point-in-time
/ snapshot read (out of scope) — it asserts a *lower bound* on freshness, not an
exact version.

## Data residency

A project may declare a `data_region` (set via `AdminService.CreateProject` /
`UpdateProject`); an instance declares the region it serves via
`GATEWAY_DATA_REGION` (validated to the same `[a-z0-9_-]`, ≤64 charset, so a
typo can't silently fail closed). When both are set and **differ**, the service
**fails closed** (`FailedPrecondition`). The guard is enforced at the connect
handler boundary while building the request Principal, so it covers **every
project-scoped RPC by construction** — Workspace/Group/Seat reads *and* writes,
the personal-workspace auto-provision, and the repo-direct Authz paths
(`ReadRelationTuples`/`DeprovisionUser`/`ExportSubjectGrants`) — not just the
data plane; the data-plane methods also guard internally as defense in depth.
The `AdminService` is intentionally exempt: it is the region-agnostic control
plane that *configures* a project's region. When either side is empty the
instance is **region-agnostic** and serves the project (today's behavior); the
check short-circuits with zero overhead. A region pin/repin is recorded in the
admin audit log (`region_changed`), and the default project is seeded with the
instance's region at bootstrap (a pre-existing default project pinned to a
different region fails fast at boot).

**Today vs. tomorrow.** This is the recording + validation + **serving guard**
half. The actual multi-region storage **routing** (steering a project's reads and
writes to a regional store, data movement on a region change) is forward-compat —
not implemented here. The guard ensures correctness in the interim: an instance
only ever touches data for the region it is configured to serve.

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

## Product-defined domain roles (per-project models)

The built-in `workspace`/`group`/`resource` namespaces are the *default* model.
A product does **not** edit `pkg/authz/model.go` to get its own role vocabulary
— it registers a per-project model through `AdminService` (gated by the admin
secret), and that model is **overlaid** on the defaults for that project only:

```
AdminService.CreateProject{ id: "edu", model_json: "<model>" }
```

The `model_json` is a map of `namespace → relation → rewrite`, where each rewrite
is one of `{"this":true}`, `{"computed":"rel"}`,
`{"tupleToUserset":{"tupleset":"rel","computed":"rel"}}`, `{"union":[…]}`,
`{"intersection":[…]}`, or `{"exclusion":{"include":…,"exclude":…}}`.

A learning platform's **instructor ⊃ ta ⊃ learner** hierarchy, with permissions
computed off the roles and content that inherits from its course:

```json
{
  "course": {
    "instructor": {"this": true},
    "ta":         {"union": [{"this": true}, {"computed": "instructor"}]},
    "learner":    {"union": [{"this": true}, {"computed": "ta"}]},
    "can_manage": {"computed": "instructor"},
    "can_grade":  {"computed": "ta"},
    "can_view":   {"computed": "learner"}
  },
  "content": {
    "parent": {"this": true},
    "viewer": {"union": [{"this": true}, {"tupleToUserset": {"tupleset": "parent", "computed": "learner"}}]},
    "editor": {"union": [{"this": true}, {"tupleToUserset": {"tupleset": "parent", "computed": "instructor"}}]}
  }
}
```

Grant `course:c1#instructor@user:alice` and `Check(course, c1, can_grade, alice)`
is true (instructor ⊃ ta ⊃ can_grade); a `learner` is not. `content` parented to
the course inherits: `Check(content, lesson1, editor, alice)` flows up via
`tupleToUserset(parent, instructor)`. Three guarantees hold and are tested:

- **Overlay** — the built-in `workspace`/`group`/`resource` surface still works
  in the project; a custom namespace only *adds* (or, by re-declaring a name,
  overrides) namespaces.
- **Isolation** — the `course` namespace and its grants exist only in project
  `edu`; the same `Check` in another project denies.
- **Validation** — on `CreateProject` a model whose same-namespace
  `computed`/`tupleset` reference is undeclared is rejected, so a typo surfaces
  at write time rather than silently denying.

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
