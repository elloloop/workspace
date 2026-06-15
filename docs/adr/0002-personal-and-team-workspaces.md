# ADR-0002 — Personal-by-default workspaces, and the personal/team split

## Status

Accepted (2026-06-15).

Builds on [ADR-0001](0001-relation-tuples-as-the-authz-primitive.md): a
workspace is an object in the `workspace` namespace, and its membership is a set
of relation tuples. This ADR decides the *product* shape of that namespace.

## Context

The products this service backs span a spectrum from pure B2C to pure B2B:

- A **personal-assistant** user works alone and occasionally shares a task with
  a relative. They have no company.
- A **learning-platform** user might be an individual buyer *or* an employee
  whose company bought seats.
- A **workplace collaboration** user is always inside a company.

Claude and ChatGPT model exactly this spectrum with two workspace kinds: every
account has a personal space that exists from the moment you sign in, and you
can additionally create or join team workspaces. We want the same shape so a
single account can be a B2C user in one context and a team collaborator in
another, with no separate "upgrade to org" signup.

The design questions are: (1) does a workspace exist before the user creates
one, and (2) is "personal" just a team workspace with one member, or is it a
distinct, constrained kind?

## Decision

1. **Every user owns exactly one personal workspace, auto-provisioned.**
   `WorkspaceService.ListWorkspaces` provisions the caller's `PERSONAL`
   workspace on first call (`WorkspaceType.WORKSPACE_TYPE_PERSONAL`). The user
   never creates it and never has a "no workspace" state — they always have
   somewhere to own resources.

2. **Personal workspaces are closed.** A personal workspace admits exactly one
   member, the owner, and **cannot be deleted**. `AddMember`, `CreateInvitation`,
   and `DeleteWorkspace` are rejected for it. It is a stable, private home for a
   single user's resources — the B2C surface.

3. **Team workspaces are the collaboration surface.** `CreateWorkspace` makes a
   `TEAM` workspace (`WORKSPACE_TYPE_TEAM`) the caller owns. A team is anything
   from a family to a whole company; it takes members via `AddMember` /
   invitations, each at a role (`owner` ⊃ `admin` ⊃ `member` ⊃ `guest`), and it
   can be deleted by its owner.

4. **Personal and team are distinct kinds, not one with a member count.** The
   `WorkspaceType` enum is explicit so the closed-ness of personal workspaces is
   enforced structurally, not inferred from "happens to have one member". A team
   workspace that drops to one member is still a team workspace; a personal
   workspace can never become a team.

Both kinds are the same `workspace` namespace object underneath: membership is
mirrored as `workspace:<id>#<role>` tuples, so `Check` and resource inheritance
(ADR-0001) treat them identically.

## Consequences

- **Positive.** One account spans B2C and B2B with no mode switch. A
  personal-assistant user and a BigCo employee are the same identity; the
  difference is which workspace a resource is parented to.
- **Positive.** Auto-provisioning removes the "empty account" edge case — there
  is always an owner workspace for a user's first resource, task, or course.
- **Positive.** Closing the personal workspace makes a clear privacy guarantee:
  a user's personal space can never accidentally gain a second member or be
  destroyed.
- **Negative.** The personal/team asymmetry is special-cased in
  `WorkspaceService` (rejected mutations on personal workspaces). This is
  intentional product policy, but it is logic that a uniform "just a workspace"
  model would not need.
- **Negative.** A user who wants to collaborate must create a team workspace and
  move (or re-parent) resources into it; there is no "promote my personal
  workspace to a team". This keeps personal workspaces private at the cost of a
  migration step — accepted, and mirrors how Claude/ChatGPT keep personal and
  team plans separate.
