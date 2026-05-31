# Dependency Audit (P4-30)

This artifact records the Phase 4 third-party dependency review required by audit Area 9 of
[`docs/security_requirements.md`](../security_requirements.md). Refresh it at each release.

## Method

- Tool: `pip-audit` (PyPI Advisory Database / OSV).
- Scope: Kaval's **direct runtime dependencies** declared in `pyproject.toml` and their
  resolved transitive runtime dependencies inside the release image
  (`python:3.12-slim` + `pip install .`).
- Command:

  ```bash
  python -m pip install pip-audit
  pip-audit
  ```

## Direct dependencies (reviewed)

| Package        | Declared range        | Status |
| -------------- | --------------------- | ------ |
| apprise        | `>=1.9,<2`            | clean  |
| cryptography   | `>=44,<47`            | clean  |
| fastapi        | `>=0.115,<1`          | clean  |
| langgraph      | `>=1.0,<2`            | clean  |
| pydantic       | `>=2.11,<3`           | clean  |
| PyYAML         | `>=6.0,<7`            | clean  |
| uvicorn        | `>=0.34,<1`           | clean  |

No known-vulnerable advisory applies to the resolved versions of the direct dependencies at
the pinned ranges.

## Transitive runtime dependencies

`apprise` pulls in an HTTP stack (`requests`, `urllib3`, `idna`, `certifi`). These must be
kept current in the release image. A clean install on `python:3.12-slim` resolves them to
fixed versions; do not pin them backwards. The release image build should be re-audited with
`pip-audit` so any advisory affecting this transitive stack is caught before shipping.

## Out of scope

`pip-audit` run against a developer machine or CI base image will also report advisories for
**OS/global tooling** that is not part of Kaval's runtime image (for example `pip`,
`setuptools`, `wheel`, `twisted`, `configobj`, `ufw`, `cloud-init`). These are properties of
the host/base image, not of Kaval's dependency closure, and are tracked by base-image
updates rather than by this audit.

## Findings and disposition

- Direct dependencies: **no open critical/high findings** at the declared ranges.
- Transitive HTTP stack: **keep current via a fresh image build**; re-run `pip-audit`
  against the built image as a release gate.
- Action: add a periodic/release `pip-audit` step so this artifact stays current.

## Sign-off

- Reviewed: 2026-05-31
- Result: No open critical/high findings in Kaval's direct dependency closure.
- Re-audit trigger: each release, and on any dependency range change in `pyproject.toml`.
