# Documentation Index

Scope: single source of truth for "which note answers which question."
Every doc under `docs/` is listed here with a 1–2 sentence summary of what
it covers. When adding a new doc, add a row here — don't duplicate this
table elsewhere (`../../CLAUDE.md` links here instead of repeating it).

| Note | What it's for |
|---|---|
| [`architecture/system-overview.md`](../architecture/system-overview.md) | Why the dashboard and the Wazuh manager are split into two components with different trust levels, why there are now two channels between them, and what each one owns. Start here for any architectural question. |
| [`architecture/wazuh-api.md`](../architecture/wazuh-api.md) | What this deployment's Wazuh API actually does, **as measured rather than as documented**: the three transport rules that are not optional, the error shapes that hide inside HTTP 200, the per-endpoint Content-Type differences, and why this manager is slow. Read before writing any code that calls the manager. |
| [`architecture/execution-flow.md`](../architecture/execution-flow.md) | How a request actually moves step-by-step at runtime (alert ingestion, the API read-modify-write cycle, the residual SSH path, agents/groups) for flows that aren't obvious from reading one file alone. |
| [`architecture/repository-map.md`](../architecture/repository-map.md) | Pure navigation: where each capability lives in the repo tree, file by file. No rationale, just location. |
| [`development/coding-standards.md`](../development/coding-standards.md) | Repo-specific conventions to follow when writing or editing code (typing style, English-throughout rule, the backend module split and its patch-target conventions, XML-via-lxml rule, etc.) that aren't obvious from PEP 8 alone. |
| [`development/workflow.md`](../development/workflow.md) | How to change this repo safely — which changes are dashboard-only, manager-only, or touch the SSH contract, and what coordinated edits each requires. |
| [`development/testing.md`](../development/testing.md) | What the `pytest` suite covers (dashboard-side logic) versus what requires a real Wazuh manager (manager-side scripts), plus the patching conventions the suite depends on. |
| [`development/deployment.md`](../development/deployment.md) | Where each artifact actually runs (dashboard machine vs. manager), fixed install paths, and the manager-side permission model. |
| [`security/ssh-boundary.md`](../security/ssh-boundary.md) | The threat model and invariants for the **residual** SSH channel — now four dispatch targets, not six — and what a fully compromised dashboard key can and can't do with it. |
| [`security/dashboard-side.md`](../security/dashboard-side.md) | Auth, session, and secret handling in the dashboard backend — including the **Wazuh API credential and its unscoped RBAC**, which is the largest open risk in the project. |
| [`security/manager-side.md`](../security/manager-side.md) | The validation, backup, and identity-confirmation guarantees the manager-side tools provide, and why the manager (not the browser form) is the real trust boundary. |
| [`knowledge/design-decisions.md`](design-decisions.md) | Decisions and their rejected alternatives (e.g. why restricted SSH instead of a second HTTP API), kept in one place so other docs can reference rather than re-derive them. |
| [`knowledge/common-pitfalls.md`](common-pitfalls.md) | Traps specific to this repo's architecture that look like bugs but are known, documented gotchas (e.g. `localhost` as `hook_url`, NAT-only VM networking). |
