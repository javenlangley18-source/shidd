Security design — PrivacyShield

Overview

This document outlines a minimal, non-destructive security design for PrivacyShield focused on: intrusion detection & logging, account lockout and rate limiting, and a safe secure-purge workflow for administrators. The design prioritizes auditability, least privilege, and safe defaults (no irreversible destructive operations without multi-step confirmation and audit records).

Key goals

- Detect and log suspicious activity with clear audit trails.
- Prevent brute-force and automated abuse with lockouts and rate limits.
- Provide a safe, auditable, admin-only secure-purge workflow that quarantines data before final deletion and requires multi-step confirmation and recorded justification.

Integration points

- PermissionAudit.swift: attach audit logging hooks when summaries are produced or exported.
- TrackerBlocker.swift: ensure decisions and updates to blockedDomains are logged and authenticated when modified.
- Add a thin AuditLog API (append-only) in the core or an adjacent module to collect security events.

Intrusion detection & logging

- Record high-value events: failed auth attempts, privilege escalations, changes to blocklists, purge operations, and admin logins.
- Use an append-only AuditEvent structure: timestamp, actor (user id / admin id / system), action type, target resource, action details, request origin (IP/user-agent) when available.
- Ensure logs are tamper-evident: include event hashes or store in an append-only remote store in production.

Account lockout & rate-limiting

- Implement exponential backoff or temporary account lockout after configurable failed attempts.
- Rate-limit high-risk endpoints (login, purge, modify blocklist) using token-bucket or leaky-bucket semantics.
- Provide admin endpoints to view lockout state and to safely unlock accounts with an audit record.

Secure data purge (safe, auditable workflow)

1. Quarantine: when a purge is requested, the system moves/marks data as 'quarantined' instead of immediate deletion. Quarantined data remains recoverable for a configurable retention (e.g., 7 days).
2. Justification & Approval: purge requests must include a textual justification and be initiated by an admin user. For high-sensitivity items require a second approver (2-person rule) or a time-delayed auto-approval window.
3. Audit & Notification: record the request, approver(s), and the final action in the AuditLog and notify stakeholders (email/webhook) if configured.
4. Final Deletion Window: after approval, apply a configurable delay (e.g., 24-72 hours) before irreversible deletion; keep deletion logs with event hashes.
5. Test & Rehearse: provide a 'dry-run' mode that simulates purge effects without changing data.

Safety controls

- Only code paths explicitly marked admin-only may perform quarantine/approve/final-delete operations.
- All admin actions require authentication and must be logged.
- Provide a UI and CLI path that requires explicit confirmation (type the resource id or passphrase) before final deletion.
- Provide reversible path during quarantine; deletion requires recorded justification and waiting period.

Testing & CI

- Add unit tests for AuditLog, quarantine/restore flows, and permission checks.
- Add integration tests that simulate failed auth, lockout triggers, and purge request/approval lifecycle.
- Run tests in CI (existing swift-ci workflow) — add focused security tests to the matrix.

Next steps / roadmap

- Implement an AuditLog type and wire it into PermissionAudit and other critical code paths (low friction, append-only API).
- Implement quarantine and purge scaffolding: API endpoints/CLI commands, storage flags for quarantined state, and dry-run behavior.
- Add rate-limiting and account lockout primitives (configurable thresholds).
- Add automated CI security tests and sample audit log readers for investigations.

Notes

This document contains only design and safe, non-destructive steps. Any irreversible deletion tool must require explicit approvals, be logged, and include a quarantine period by default.
