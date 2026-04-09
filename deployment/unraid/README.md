# Private Unraid Packaging

This directory is intentionally scoped to private and self-hosted Unraid testing.
It does not represent a public Community Apps submission.

- `kaval.xml`: canonical Unraid Docker template for the current single-container, two-internal-process runtime.
- `kaval.yaml.example`: reference for the non-secret settings that persist to `/data/kaval.yaml`.

Template assumptions:

- The image tag defaults to `ghcr.io/rejozmathew/kaval:private-testing`.
- Persistent application state lives under `/data` inside the container.
- The internal executor process still requires `/var/run/docker.sock` for approval-gated restart actions.
- First-run setup still happens in the Kaval web UI after the container starts.

The template leaves the icon empty on purpose for this private-testing tranche. That avoids implying public-release readiness or depending on a Community Apps asset pipeline before Unraid validation is complete.

Private deployment flow:

1. Run the `Private Image` GitHub Actions workflow and push the `private-testing` tag to GHCR.
2. If the GHCR package is private, add a GHCR login in Unraid with a token that can read packages.
3. Import `kaval.xml` into Unraid from the raw GitHub URL or place it under `/boot/config/plugins/dockerMan/templates-user/`.
4. Set the `/data` appdata path, choose a host port for `9800`, and provide a strong `KAVAL_APPROVAL_HMAC_SECRET`.
5. Optionally pre-seed `/data/kaval.yaml` from `kaval.yaml.example` before first boot; secrets still belong in the UI/vault or one-time environment bootstrap.
6. Start the container and finish configuration in the Kaval web UI.

For local or non-Unraid smoke testing, the repo-root `docker-compose.yml` and `.env.example` mirror the same runtime shape and image tag.
