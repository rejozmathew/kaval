# ADR-007: Do Not Fork or Replace Uptime Kuma

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval overlaps slightly with existing monitoring tools, but its value proposition is investigation, causal reasoning, and action safety rather than status pages or time-series dashboards. Competing head-on with mature monitoring products would dilute the core product.

## Decision

Kaval will integrate with tools such as Uptime Kuma, Grafana, Prometheus, and Netdata instead of trying to replace or fork them. Uptime Kuma is explicitly treated as an external alert source, not as Kaval's product baseline.

## Consequences

- Kaval stays focused on findings, incidents, investigations, and recommendations.
- Status pages, multi-location probing, and dashboard replacement remain out of scope for v1.
- Webhook ingestion and alert normalization become integration work rather than product reinvention.
- Product positioning remains complementary instead of competitive with existing monitoring stacks.
