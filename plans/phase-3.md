# Phase 3 — Webhook Integration + Operational Memory UX + Polish

## Objective
Integrate with existing monitoring tools, make Operational Memory user-editable, and prepare for early adopters.

## Deliverables
- Webhook receiver + normalizers (Uptime Kuma, Grafana, Prometheus, Netdata)
- Prometheus `/metrics` endpoint
- User notes via UI and Telegram
- Operational Memory browser UI (journal, notes, system profile)
- Recurrence reports and permanent-fix suggestions
- Homepage/Homarr widget API
- External API integrations (Cloudflare, Authentik; investigation-time, UAC)
- Additional service descriptors
- Settings/configuration UI
- Audit trail UI
- Model usage / cost dashboard
- Auto-generated descriptor support with quarantine rules

## Proposed workstreams
- Webhooks and metrics
- Operational Memory UX
- External integrations
- Descriptor expansion and quarantine enforcement
- Settings/audit/cost visibility

## Exit criteria
- Uptime Kuma webhook can trigger investigation flow
- Grafana/Prometheus alerts can be ingested and normalized
- User notes can be created and safely filtered into investigation context
- Memory browser is usable in UI
- Additional descriptors pass contract tests
- Audit trail UI shows actions and approvals

## Notes
- This phase can be broken into TaskMaster tasks after P2B based on actual code shape.
- Keep the same review model: small branches, tests required, security review for sensitive areas.
