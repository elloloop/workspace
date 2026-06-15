<!--
Thanks for contributing. Fill out the sections below before requesting review.
The CI pipeline (lint + vuln + test + smoke + integration + realpostgres + conformance + docker) must be green to merge.
-->

## Summary

<!-- One-paragraph description of what changes and why. Link the issue this closes. -->

Closes #

## What changed

<!-- Bullet list of the substantive changes. Skip for trivial PRs. -->

-

## Test plan

<!--
How did you verify this works? Be specific.
For bug fixes: include a regression test in the diff and reference it here.
For features: list the tests you added (unit / integration / realpostgres / conformance).
-->

- [ ] Added or updated unit tests
- [ ] Added or updated integration tests (`-tags=integration`)
- [ ] Added or updated real-DB tests (`-tags=realpostgres`) if behavior depends on storage
- [ ] Extended the repo conformance suite if a driver or its semantics changed
- [ ] Documented public-facing changes in `docs/`

## Risk

<!-- What could break? What's the blast radius? Multi-replica considerations? -->

## Backward compatibility

<!-- Does this change a wire format, env var, schema, or public API? If yes, describe migration. -->

## Engineering rules checklist

See [AGENTS.md](../AGENTS.md). The following must be true:

- [ ] No patch fixes / shims / compatibility layers - wrong shapes are fixed, not wrapped
- [ ] No dead code left behind from a refactor
- [ ] No half-finished implementations (impl + tests + wiring all land together)
- [ ] Bug fixes ship with regression tests
- [ ] Commit messages are imperative, no AI attribution, no inaccessible-context references

## Contributor License Agreement

First-time contributors will see a CLA status check on this PR. To sign,
read [CLA.md](../CLA.md) and comment on this PR with exactly:

> I have read the CLA Document and I hereby sign the CLA

The check turns green once your signature is recorded. Returning
contributors are remembered automatically; sign once.
