# Security policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/elloloop/workspaces/security/advisories/new).

Include:

- A description of the vulnerability and its impact.
- A repro: steps, payload, affected version.
- Whether you have already disclosed this to anyone else.

We aim to acknowledge reports within 2 business days and to publish a fix within 30 days for high/critical issues.

## Supported versions

The most recent minor release receives security fixes. Older minor versions are best-effort.

## What we treat as a vulnerability

- Authentication or authorization bypass.
- Privilege escalation (non-admin → admin, cross-user or cross-workspace data access).
- Membership or role enumeration, workspace-takeover vectors.
- Token forgery, signature-verification bypass, JWKS spoofing.
- Information disclosure (PII, tokens, relation tuples) in responses or logs.
- Denial-of-service vectors that an unauthenticated caller can trigger at low cost.
- Supply-chain compromise (dependency, container image, GitHub Actions workflow).

Bugs that affect correctness but not security should be filed as regular issues.
