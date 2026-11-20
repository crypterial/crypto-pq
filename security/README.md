# Security records

This folder holds the records of the security reviews of crypto-pq: what was examined, at which
commit, how, what was found, how each finding was fixed and what the review did not cover.

- [audit-2026-11.md](audit-2026-11.md): the source audit of November 2026, an AI-assisted audit run
  by the maintainer on commit c48e64f, the fixes that followed it, up to decision D-119, and what
  the releases 1.0.0 and 1.0.1 leave.

The rules that the crate follows are in the specification, not here.
[Section 14](../spec/14-security.md) states the security requirements: constant time,
data-independent timing, entropy, self-tests, wiping and memory.
[Section 14.8](../spec/14-security.md#148-security-considerations) collects the limits that
callers and deployments must know, and [`spec/decisions.md`](../spec/decisions.md) records the
reason for each choice.

To report a vulnerability, follow [SECURITY.md](../SECURITY.md).
