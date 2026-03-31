# Kaval (കാവൽ)

## Product Requirements, Reference Architecture, and Agentic Build Plan

**Version:** 4.1  
**Date:** March 30, 2026  
**Author:** Rejo Z. Mathew  
**Status:** Implementation-ready

---

## Document Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-03-29 | Initial requirements (Microsoft Agent Framework, skills-based) |
| 2.0 | 2026-03-29 | Complete redesign: LangGraph, two-layer architecture, service descriptors, auto-discovery |
| 3.0 | 2026-03-30 | Added: Incident model, Core/Executor split, three-tier actions, investigation chain, Operational Memory, non-goals, success metrics, edge confidence, descriptor quarantine rules |
| 4.0 | 2026-03-30 | Consistency pass: evidence/inference/recommendation framing, v1 flagship aligned to restart scope, Operational Memory trust model + redaction, causal taxonomy, Phase 2 split into 2A/2B, success metrics engineering/product split, ADR governance |
| 4.1 | 2026-03-30 | Contract patch: Executor docker.sock clarification, OpenAI-compatible wording throughout, offline degraded-mode behavior, local-safe vs cloud-safe redaction levels, approval token contract, frozen Phase 0 interfaces, cause confirmation source field, metrics enforcement clarification |

---

## 1. Executive Summary

Kaval (കാവൽ, Malayalam for "guard / watchkeeper") is a self-hosted, auto-discovering, AI-powered observability and investigation platform for Unraid-based homelab infrastructure. It continuously monitors the entire Unraid ecosystem — the OS itself, Docker containers, VMs, plugins, network services, and external dependencies — and when something breaks, it investigates autonomously by gathering evidence across the affected services, determines the most likely root cause, presents a structured evidence trail with its inference and confidence level, and proposes remediations with explicit risk assessment.

Kaval is not another monitoring dashboard. Monitoring tools like Uptime Kuma detect that something is down. Kaval explains the most likely cause, shows the evidence it collected, and proposes how to fix it with a risk assessment. It sits alongside existing monitoring tools, not in competition with them.

### Core Value Proposition

Install Kaval from Unraid Community Applications. Provide one Unraid API key. Kaval auto-discovers every container, VM, share, plugin, and service on your server. It matches known services against a built-in library of 50-100 common homelab Docker images. It infers dependency chains. It starts monitoring immediately — zero configuration. When something breaks, the agent autonomously gathers evidence (reads logs, inspects container configs, checks image history, probes endpoints, queries dependency health), reasons about root cause using AI, fetches changelogs and release notes to assess impact, and presents a structured investigation to the user with evidence, inference, and a recommended action with risk assessment.

**What you install depends on what you need:**
- **Monitor mode:** One container + Unraid API key. Auto-discovery, health checks, alerts, dependency map.
- **Assist mode:** One container + a local OpenAI-compatible model endpoint (e.g., Ollama, LM Studio, vLLM). Adds AI investigation and root-cause analysis.
- **Operate mode:** Core container + Executor sidecar + local model endpoint. Adds bounded action execution with approval.

### Key Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Deployment | Docker: Core container + optional Executor sidecar | Core is unprivileged; Executor holds bounded action capability |
| Primary system boundary | Unraid 7.2+ native GraphQL API | Built-in, authenticated, comprehensive |
| Orchestration framework | LangGraph (Python, GA since Oct 2025, v1.0.10) | Production-proven, model-agnostic, built-in checkpointing and HITL |
| Local LLM | Any OpenAI-compatible endpoint (e.g., Ollama, LM Studio, vLLM) | Free, private, runs on existing GPU hardware |
| Cloud LLM (optional) | Anthropic Claude / OpenAI GPT (configurable) | For complex multi-service root cause and changelog research |
| Monitoring approach | Two-layer: deterministic checks + LLM investigation | 85% of monitoring value needs no LLM; AI reserved for investigation |
| Action model | Three-tier: evidence gathering → research → remediation | Read-only investigation is autonomous; only remediation needs approval |
| Service knowledge | YAML descriptor library + auto-generation | Community-extensible, no code needed to add services |
| Credential model | Just-in-time, volatile by default, optional encrypted vault | No upfront credential collection; UAC-style access |
| Operational memory | System profile + investigation journal + user notes | Agent learns from past incidents and server-specific quirks |
| Notification library | apprise (Python, 80+ services) | One dependency covers Telegram, ntfy, Discord, email, and more |
| Frontend | React with dependency graph visualization | Hero feature: Coroot-inspired service map with live health |
| Backend API | FastAPI | Async Python, automatic OpenAPI docs, WebSocket support |
| Database | SQLite | Simple, zero-config, sufficient for single-server homelab |

### Primary Goal

Learning enterprise-grade agent architecture through a realistic, bounded domain while producing a genuinely useful open-source product.

### Secondary Goal

Create an extensible platform that other Unraid and homelab users can adopt and contribute to.

---

## 2. Product Vision and User Experience

### 2.1 The Problem

Homelab servers running Unraid with 20-30 Docker containers, VMs, reverse proxies, DNS/tunnel configurations, identity providers, and media automation create a complex, interdependent system. When something breaks:

1. The user discovers the problem manually or gets a basic "DOWN" alert
2. They SSH in or open various dashboards to check container status
3. They read logs across multiple services trying to find the failure
4. They mentally trace dependency chains (NPM → Cloudflare, Radarr → Prowlarr → DelugeVPN)
5. They google error messages, check changelogs, cross-reference with recent changes
6. They try fixes, often in the wrong order, sometimes making things worse

This process takes 30 minutes to several hours. The NPM/Cloudflare TLS breakage in March 2026 is a representative example: the site went down, the container was running, the cert was valid, but a Docker image auto-update introduced an OpenSSL version that broke compatibility with Cloudflare origin certs. Finding that root cause required checking 4 different systems and understanding a subtle version interaction.

### 2.2 The Solution

Kaval automates steps 2-6. It already knows what's running (auto-discovery), already knows what depends on what (dependency graph), already monitors health (deterministic checks), and when something breaks, it gathers evidence across the affected chain, reads changelogs, correlates with recent changes, identifies the most likely root cause, assesses remediation risks, and presents everything transparently. The user's experience changes from "debug for 2 hours" to "read a Telegram message, review the evidence, and approve a fix."

### 2.3 The Investigation Chain (the core product experience)

This is the full workflow Kaval performs when it detects a failure. Kaval produces three structured outputs: **evidence** (facts collected), **inference** (conclusions drawn), and **recommendation** (proposed action + risk assessment).

**v1 Flagship Example: DelugeVPN tunnel drop cascading to Radarr and Sonarr**

```
EVIDENCE (collected autonomously, no approval needed):

  1. ✅ Container state: DelugeVPN running, Radarr running, Sonarr running
  2. ✅ DelugeVPN logs (last 200 lines): "VPN tunnel inactive" since 14:23
  3. ✅ Radarr health endpoint: returning errors
  4. ✅ Radarr logs: "Download client not available"
  5. ✅ Sonarr logs: "Download client not available"
  6. ✅ Prowlarr health: healthy ✅ (eliminates indexer as cause)
  7. ✅ Dependency graph walk: Radarr → DelugeVPN, Sonarr → DelugeVPN
  8. ✅ Operational Memory: DelugeVPN tunnel drop has occurred 3 times
     before. Restart resolved it each time.

INFERENCE:

  Root cause: DelugeVPN lost its VPN tunnel at 14:23.
  Radarr and Sonarr are failing because their download client
  (DelugeVPN) is unreachable — not because of their own issues.
  Prowlarr (indexers) is healthy, confirming the failure is
  downstream in the download path only.
  Confidence: High (from logs + dependency graph + prior history)

RECOMMENDATION:

  Action: Restart DelugeVPN container
  Risk: Low (reversible, no data loss, restart resolved this 3 times)
  Past history: This is occurrence #4. Consider permanent fix
  (health check auto-restart or switching to Gluetun).

  [✅ Approve restart]  [🔍 Full details]  [❌ Dismiss]
```

**This investigation chain IS the product.** The agent collects evidence, draws inferences, and proposes a recommendation — transparently and with full traceability.

**v2+ Example: NPM TLS breakage (demonstrates Tier 2 research + rollback)**

In later versions with Tier 2 research and image rollback capability, the investigation chain extends to include changelog research, version comparison, and risk-assessed rollback:

```
EVIDENCE:
  1-6. Container state, logs (SSL handshake failure), image change
       detection (v2.12.0 → v2.12.1), TLS cert valid, Cloudflare OK

RESEARCH (v2 capability):
  7. GitHub changelog: "Upgraded Alpine base with OpenSSL 3.5.5"
  8. Version comparison: no DB migrations, no config schema changes
  9. System profile: SSL strategy = Cloudflare origin certs

INFERENCE:
  OpenSSL 3.5.5 dropped cipher support needed by Cloudflare origin certs.

RECOMMENDATION:
  Roll back NPM to v2.12.0 (low risk: no migrations, old image cached)
```

### 2.4 Install Experience

```
Step 1: Install "Kaval" from Unraid Community Applications
Step 2: Open Kaval web UI at http://[server-ip]:9800
Step 3: Enter Unraid API key (generated from Settings → Management Access)
Step 4: (Optional) Enter Telegram bot token for notifications
Step 5: Click "Initialize"

Kaval response (30-60 seconds):

  ✅ Connected to Unraid API
  ✅ Discovered 25 containers (22 matched to known services, 3 unknown)
  ✅ Discovered 3 VMs (Ubuntu Server, Home Assistant, Windows 11)
  ✅ Discovered 8 user shares (4.2 TB used of 12 TB)
  ✅ Array: healthy, parity valid (last check: 3 days ago)
  ✅ Cache pool: healthy (2x NVMe, RAID 1)
  ✅ Inferred 47 dependency relationships
  ✅ System profile saved to Operational Memory
  ✅ Monitoring active

  "I'll notify you when something needs attention."
```

### 2.5 Install Profiles

| Profile | Capabilities | Credentials needed |
|---------|-------------|-------------------|
| Monitor | Auto-discovery, health checks, dependency map, alerts, dashboard | Unraid API key only |
| Assist | Monitor + AI investigation, root-cause analysis, remediation proposals | Unraid API key + local model endpoint (e.g., Ollama) |
| Operate | Assist + bounded action execution with approval (requires Executor sidecar) | Unraid API key + local model endpoint + Executor container |

Default: **Monitor** mode. Investigation features activate when a local model endpoint is detected. Action execution requires the Executor sidecar and explicit opt-in.

### 2.6 Non-Goals (v1)

Kaval v1 is explicitly NOT:

- **A replacement for Prometheus/Grafana.** Kaval does not collect time-series metrics, build custom dashboards, or store historical performance data. It integrates with these tools as alert sources.
- **A replacement for Uptime Kuma.** Kaval does basic endpoint probing for investigation, but does not provide status pages, response time history, or multi-location checks. It accepts Uptime Kuma webhooks.
- **A generic AIOps platform.** Kaval is purpose-built for Unraid homelabs. It is not designed for Kubernetes, cloud infrastructure, or enterprise data centers.
- **A self-healing platform.** Every remediation requires explicit user approval. Kaval proposes actions; it does not execute them autonomously.
- **A config management system.** Kaval does not manage Docker Compose files, infrastructure as code, or declarative state.
- **A multi-server product (v1).** Kaval monitors one Unraid server. Multi-server support is a future goal.
- **An autonomous remediation engine.** The human is always in the loop for any action that changes system state.
- **A general-purpose AI assistant.** Kaval investigates infrastructure problems. It does not answer general questions, write code, or perform unrelated AI tasks.

---

## 3. Architecture Overview

### 3.1 Core/Executor Architecture

Kaval runs as two containers with distinct trust boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│  KAVAL CORE (unprivileged, non-root)                        │
│                                                             │
│  Discovery, monitoring, investigation, UI, notifications,   │
│  credential vault, operational memory, API                  │
│                                                             │
│  CAN: read Docker API (via Unraid API), read Unraid API,    │
│       probe endpoints, read container logs, call LLMs,      │
│       send notifications                                    │
│                                                             │
│  CANNOT: restart containers, pull images, start/stop VMs,   │
│          modify any system state                            │
│                                                             │
│  NO docker.sock mount. NO host access.                      │
└────────────────────┬────────────────────────────────────────┘
                     │ Internal API (localhost only)
                     │ Requests: {action, target, approval_token}
                     │ Allowlist-checked, audit-logged
┌────────────────────▼────────────────────────────────────────┐
│  KAVAL EXECUTOR (optional sidecar, minimal privileges)      │
│                                                             │
│  Tiny container with docker.sock mount and a strict         │
│  action allowlist. This is the ONLY container with          │
│  docker.sock access.                                        │
│                                                             │
│  Privileged interfaces:                                     │
│    • Docker socket (/var/run/docker.sock) for container ops │
│    • Unraid API (scoped key) for VM start/stop (v2+)        │
│                                                             │
│  Receives approved action requests from Core via localhost.  │
│  Verifies approval token (single-use, time-limited,         │
│  incident-bound, HMAC-signed). Executes. Reports result.    │
│                                                             │
│  CAN: restart one named container (v1)                      │
│  v2+: + pull specific image tag, start/stop one named VM    │
│  CANNOT: delete anything, modify configs, call external     │
│          APIs, access internet, read Core's secrets          │
│                                                             │
│  v1 allowlist: restart_container                            │
│  v2 allowlist: + pull_specific_image_tag, start_vm, stop_vm │
│  v3 allowlist: + modify_config_with_backup                  │
└─────────────────────────────────────────────────────────────┘
```

This separation ensures the Core (which has network access, LLM integration, and UI exposure) never has docker.sock or direct system-modification capability. The Executor (which has docker.sock) has no network access, no LLM access, no UI, and only accepts HMAC-verified requests from Core on localhost.

**Users who choose Monitor or Assist profiles don't need the Executor at all.** The Executor sidecar is only required for Operate mode.

### 3.2 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     KAVAL CORE                              │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  LAYER 1: MONITORING (deterministic, always-on)      │   │
│  │                                                      │   │
│  │  Scheduler → Checks → Findings → Incidents           │   │
│  │                                                      │   │
│  │  Checks:                                             │   │
│  │  • Container health (Docker API)                     │   │
│  │  • Endpoint probes (httpx)                           │   │
│  │  • TLS/cert validation (ssl module)                  │   │
│  │  • DNS resolution (dns.resolver)                     │   │
│  │  • Log pattern matching (regex)                      │   │
│  │  • Unraid system health (GraphQL API)                │   │
│  │  • VM state (Unraid API)                             │   │
│  │  • Plugin health (Unraid API)                        │   │
│  │  • Dependency chain validation                       │   │
│  │  • Change detection (image updates, config drift)    │   │
│  │                                                      │   │
│  │  No LLM. No service API keys. Pure Python.           │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                   │
│                (Incident triggers investigation)             │
│                         │                                   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │  LAYER 2: INVESTIGATION ENGINE (LLM, on-demand)      │   │
│  │                                                      │   │
│  │  Three-tier action model:                            │   │
│  │                                                      │   │
│  │  TIER 1 — Evidence Gathering (autonomous)            │   │
│  │  Read logs, inspect configs, check image history,    │   │
│  │  probe endpoints, query service APIs (if creds       │   │
│  │  available), walk dependency graph                   │   │
│  │                                                      │   │
│  │  TIER 2 — Research (autonomous)                      │   │
│  │  Fetch changelogs from GitHub/Docker Hub,            │   │
│  │  check known issues, compare versions,               │   │
│  │  assess breaking changes, query Operational Memory   │   │
│  │                                                      │   │
│  │  TIER 3 — Remediation Proposal (requires approval)   │   │
│  │  Root cause summary with full evidence trail,        │   │
│  │  risk assessment, recommended action                 │   │
│  │                                                      │   │
│  │  Local SLM: log analysis, single-service reasoning   │   │
│  │  Cloud SOTA: complex correlation, changelog research │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                   │
│  ┌──────────────────────▼───────────────────────────────┐   │
│  │  INCIDENT MANAGEMENT                                 │   │
│  │                                                      │   │
│  │  Group findings → Create incident → Investigate      │   │
│  │  → Notify (one message per incident) → Get approval  │   │
│  │  → Execute via Executor → Verify → Close incident    │   │
│  │  → Write to Operational Memory journal               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  SUPPORTING SYSTEMS                                  │   │
│  │                                                      │   │
│  │  • Auto-discovery engine                             │   │
│  │  • Service descriptor library                        │   │
│  │  • Dependency graph (with edge confidence)           │   │
│  │  • Operational Memory (profile + journal + notes)    │   │
│  │  • Credential vault (encrypted, UAC-gated)           │   │
│  │  • Webhook receiver (Uptime Kuma, Grafana, etc.)     │   │
│  │  • Audit trail                                       │   │
│  │  • Prometheus /metrics endpoint                      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Monitoring Scope

Kaval monitors the ENTIRE Unraid ecosystem, not just Docker containers.

```
UNRAID SERVER
│
├── OS & Hardware
│   ├── Array health (normal/degraded/rebuilding/parity status)
│   ├── Disk health (SMART data, temperature, pre-fail, errors)
│   ├── Share capacity and growth rate
│   ├── Cache pool (SSD health, space, RAID status)
│   ├── Flash drive health (boot device)
│   ├── CPU / memory / network utilization
│   ├── UPS status (battery, load, runtime estimate)
│   ├── System temperature
│   ├── OS update availability
│   └── System notifications (native Unraid alerts)
│
├── Plugins
│   ├── Installed / enabled status
│   ├── Update availability
│   ├── Critical plugin health (CA, GPU Stats, Unraid Connect)
│   └── Plugin impact on services (e.g., GPU Stats → Plex transcoding)
│
├── Docker Engine
│   ├── Container state (running/stopped/restarting/unhealthy)
│   ├── Restart count and frequency (restart storms)
│   ├── Image version and recent updates (change detection)
│   ├── Resource usage (CPU, memory per container)
│   ├── Network connectivity between containers
│   ├── Exposed port reachability
│   ├── Log pattern analysis (errors, warnings)
│   ├── Health check status (Docker HEALTHCHECK)
│   └── Volume mount validation (shares accessible)
│
├── Virtual Machines
│   ├── VM state (running/stopped/paused)
│   ├── Resource allocation (vCPUs, RAM, disk)
│   ├── VM disk location (cache vs array)
│   ├── Hosted service reachability (HTTP probes)
│   └── Snapshot status
│
├── Network & Access
│   ├── WireGuard tunnel status (built into Unraid)
│   ├── Pi-hole / DNS resolver health
│   ├── Gateway / router reachability
│   ├── External connectivity (internet access)
│   └── Reverse proxy chain health
│
└── External Dependencies
    ├── Cloudflare DNS record accuracy
    ├── Cloudflare proxy / tunnel status
    ├── SSL/TLS certificate validity and expiry
    ├── ISP connectivity (basic latency/reachability)
    └── VPN provider status (for VPN-dependent containers)
```

### 3.4 Dependency Graph

The dependency graph is Kaval's primary UI view — a Coroot-inspired service map with real-time health status on every node.

**How the graph is built:**

1. **Auto-inferred from Docker:** Network links, shared volumes, port mappings
2. **Auto-inferred from service descriptors:** The `typical_dependencies` field
3. **Auto-inferred from Unraid API:** Share mounts, GPU passthrough, VM disk locations
4. **User-editable:** Manual additions/corrections via UI or YAML

**Edge confidence types:**

Every dependency edge has an explicit confidence level:

| Edge type | Source | Confidence | Investigation weight |
|-----------|--------|-----------|---------------------|
| Configured | Docker network link, shared volume, port mapping | Medium-High | Strong signal, but not proof of runtime dependency |
| Runtime observed | Active health-check dependency, verified API call (future) | High | Full weight in root-cause analysis |
| User-confirmed | Manually approved by user in UI | High | Full weight, treated as ground truth |
| Inferred | Service descriptor `typical_dependencies` | Medium | Used for hypothesis, not conclusion |
| Auto-generated | From LLM-generated descriptor | Low | Suggestion only, not used for action recommendations or incident grouping |

During investigation, the agent weighs dependency edges by confidence. A user-confirmed edge ("Radarr connects to DelugeVPN on port 58846") drives investigation strongly. A configured edge (Docker network link) is strong but not proof of runtime dependency. An inferred edge ("Radarr probably depends on a download client") is a hypothesis to explore. Auto-generated edges are not used for root-cause chain walking or incident grouping. A wrong dependency edge is worse than no edge, so low-confidence edges are treated conservatively.

**Example dependency graph:**

```
                    ┌──────────────┐
                    │  CLOUDFLARE  │
                    │  DNS + Proxy │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐     │     ┌──────▼──────┐
        │   NPM     │     │     │  CF Tunnel  │
        │  (proxy)  │     │     │ (cloudflared)│
        └─────┬─────┘     │     └──────┬──────┘
              │            │            │
    ┌─────────┼────────┐   │   ┌────────┼────────┐
    │         │        │   │   │        │        │
┌───▼──┐ ┌───▼──┐ ┌───▼───┐ ┌─▼──┐ ┌──▼───┐ ┌──▼───┐
│ Plex │ │Jelly │ │Nextcld│ │Auth│ │Immich│ │Moodle│
│      │ │ fin  │ │       │ │entk│ │      │ │ (VM) │
└──┬───┘ └──────┘ └──┬────┘ └─┬──┘ └──┬───┘ └──────┘
   │                 │        │       │
   ▼              ┌──┘    ┌───┘   ┌──┘
┌──────┐     ┌────▼───┐ ┌─▼──────▼──┐
│ GPU  │     │MariaDB │ │ Postgres  │
│      │     │        │ │ + Redis   │
└──────┘     └────────┘ └───────────┘

   ┌───────────┐
   │ Prowlarr  │
   └─────┬─────┘
         │
    ┌────┼────┐
    │         │
┌───▼──┐ ┌───▼──┐
│Radarr│ │Sonarr│
└───┬──┘ └───┬──┘
    └────┬────┘
    ┌────▼─────┐
    │DelugeVPN │──→ NordVPN (external)
    └────┬─────┘
    ┌────▼──────┐
    │ downloads │
    │  share    │
    └───────────┘
```

In the UI, each node shows health status (green/yellow/red), active finding count, and last check time. When a failure occurs, the affected dependency path highlights in red and the root cause node pulses.

### 3.5 Change Detection and Correlation

Inspired by Coroot's deployment correlation. When a failure is detected, Kaval checks:

- **Docker image changes:** What containers pulled new images in the last 24 hours?
- **Container restarts:** What restarted recently that shouldn't have?
- **Unraid system changes:** Array operations, plugin updates, configuration changes
- **External changes:** DNS record modifications, Cloudflare setting changes (if API available)

Change events are stored in a timeline and correlated with findings during investigation. This is the signal that would have immediately identified the NPM breakage: "NPM image updated 2 hours before TLS failures started. Likely related."

---

## 4. Auto-Discovery System

### 4.1 Discovery Sources

| Source | What it discovers | How |
|--------|------------------|-----|
| Unraid GraphQL API | Containers, VMs, shares, disks, array, cache, plugins, system info | API query on init + periodic refresh |
| Docker API | Container details, networks, volumes, image metadata, health checks | Docker API (via Unraid) |
| Network scanning | Exposed ports, service endpoints | Port checks on discovered containers |
| DNS probing | Domain resolution, record accuracy | DNS queries for configured domains |
| Service descriptor library | Service identity, health endpoints, log patterns, dependencies | Image name matching against shipped YAML |

### 4.2 Service Matching

When a container is discovered, Kaval matches it against the built-in service descriptor library:

```
Discovered: lscr.io/linuxserver/radarr:latest
  → Pattern match: "lscr.io/linuxserver/radarr*"
  → Matched: Radarr (services/arr/radarr.yaml)
  → Auto-configured: health endpoint port 7878, log patterns,
    dependency hints (prowlarr, download client)

Discovered: custom-internal-app:v3.2
  → No match → generic monitoring (health, restarts, port probes, log errors)
  → Optional: LLM generates a basic descriptor (quarantined, see 4.5)
```

### 4.3 Service Descriptor Format

```yaml
# services/arr/radarr.yaml
id: radarr
name: Radarr
category: arr
project_url: https://radarr.video
icon: radarr.svg

match:
  image_patterns:
    - "lscr.io/linuxserver/radarr*"
    - "hotio/radarr*"
    - "*radarr*"
  container_name_patterns:
    - "radarr*"

endpoints:
  web_ui:
    port: 7878
    path: /
  health_api:
    port: 7878
    path: /api/v3/health
    auth: api_key
    auth_header: X-Api-Key
    healthy_when: "json_array_empty"

log_signals:
  errors:
    - "Unable to connect to indexer"
    - "Download client .* not available"
    - "Import failed"
    - "Disk space"
    - "Database is locked"
  warnings:
    - "No indexers available"
    - "Queue import blocked"

typical_dependencies:
  containers:
    - prowlarr
    - name: delugevpn
      alternatives: [qbittorrent, transmission, sabnzbd]
  shares:
    - media
    - downloads

common_failure_modes:
  - trigger: "Download client .* not available"
    likely_cause: "Download client container is down or has lost VPN tunnel"
    check_first: ["delugevpn", "qbittorrent"]
  - trigger: "Unable to connect to indexer"
    likely_cause: "Prowlarr is down or its API key changed"
    check_first: ["prowlarr"]
  - trigger: "Import failed"
    likely_cause: "Permission issue on media share or hardlink failure"
    check_first: ["media share mount", "download share mount"]

investigation_context: |
  Radarr manages movie downloads. Its /api/v3/health endpoint
  returns an array of issues — empty means healthy.

  1. Indexer unreachable → check Prowlarr
  2. Download client offline → check DelugeVPN VPN tunnel
  3. Import failed → check permissions on media share
  4. Database locked → appdata may be on NFS; use local/cache
  5. Disk space → check Unraid share capacity

  API key: Settings → General → API Key

credential_hints:
  api_key:
    description: "Radarr API Key"
    location: "Radarr Web UI → Settings → General → API Key"
```

### 4.4 Pre-Shipped Service Descriptor Library

Kaval ships with descriptors for the most common homelab Docker images:

**Media:** Plex, Jellyfin, Emby, Tautulli, Kometa  
**ARR stack:** Radarr, Sonarr, Lidarr, Readarr, Bazarr, Prowlarr, Jackett, Overseerr, Ombi  
**Downloads:** DelugeVPN, qBittorrent, Transmission, SABnzbd, Gluetun  
**Networking:** Nginx Proxy Manager, Traefik, Caddy, Cloudflare DDNS, cloudflared, Pi-hole, AdGuard Home  
**Identity:** Authentik, Authelia, Keycloak  
**Cloud:** Nextcloud, Immich, Vaultwarden, Paperless-ngx, Bookstack, Gitea  
**Automation:** Home Assistant  
**Monitoring:** Uptime Kuma, Grafana, Prometheus, InfluxDB, Netdata  
**Databases:** MariaDB, PostgreSQL, Redis, MongoDB  
**System:** Portainer, Watchtower, Duplicati, Kopia

Unknown containers still get full generic monitoring.

### 4.5 Auto-Generated Descriptors (quarantine rules)

For unmatched containers, Kaval can optionally use the local LLM to generate a basic descriptor from Docker image metadata and README content. **Hard rules:**

1. Auto-generated descriptors are stored with `verified: false` and `source: auto_generated`
2. Auto-generated descriptors are **never** used for action recommendations
3. Auto-generated descriptors only enable **low-risk checks** (endpoint probing, log error scanning) — never service API calls
4. Every auto-generated descriptor must pass schema validation and policy linting
5. No auto-generated credential hints are trusted without explicit user confirmation
6. Dependency edges from auto-generated descriptors have `confidence: low` and are not used in root-cause chain walking or incident grouping
7. Auto-generated descriptors are flagged prominently in the UI for user review
8. Users can promote auto-generated descriptors to `verified: true` after review

---

## 5. Dual-Model LLM Architecture

### 5.1 Design Principle

Two tiers of AI: a local Small Language Model (SLM) for routine tasks, and an optional cloud State-of-the-Art (SOTA) model for complex reasoning. The system works fully offline with just the local model.

### 5.2 Local SLM (OpenAI-compatible endpoint)

**Provider:** Any server exposing an OpenAI-compatible `/v1/chat/completions` API  
**Examples:** Ollama, LM Studio, vLLM, LocalAI, text-generation-webui  
**Model:** Qwen3 8B, Llama 3.1 8B, or user's choice  
**Runs on:** User's existing GPU  
**Cost:** Zero  

**Tasks:**
- Log summarization and error classification
- Single-service investigation and root-cause reasoning
- Notification message formatting
- Service descriptor generation (quarantined)
- Change impact assessment ("is this image update significant?")

### 5.3 Cloud SOTA Model (optional)

**Model:** Claude Sonnet 4.6, GPT-4o, or user's choice  
**Cost:** ~$0.01-0.05 per investigation call  

**Tasks (only when local model insufficient):**
- Multi-service root cause analysis across dependency chains
- Changelog/release notes research and breaking change identification
- Complex correlation (version interactions, cipher compatibility, etc.)
- Risk assessment for proposed remediations
- Low-confidence escalation from local model

### 5.4 Escalation Policy

```yaml
models:
  local:
    provider: ollama
    model: qwen3:8b
    base_url: http://localhost:11434

  cloud:  # optional
    provider: anthropic
    model: claude-sonnet-4-20250514
    api_key_env: KAVAL_CLOUD_API_KEY

  escalation:
    use_cloud_when:
      - finding_count > 3
      - multiple_domains_affected: true
      - local_confidence < 0.6
      - changelog_research_needed: true
      - user_requests_deep_analysis: true

  cost_controls:
    max_cloud_calls_per_day: 20
    max_cloud_calls_per_incident: 3
    warn_at_daily_spend: 1.00
```

### 5.5 Three-Tier Action Model

This is the critical architectural distinction. Not all "actions" are equal.

**Tier 1: Evidence Gathering (autonomous, no approval)**

Read-only operations the agent runs freely during investigation:

| Action | Method | Risk |
|--------|--------|------|
| Read container logs (last N lines) | Docker API | None |
| Inspect container config and image metadata | Docker API | None |
| Check image pull history and version | Docker API | None |
| Query Unraid system state | Unraid GraphQL | None |
| Probe HTTP/HTTPS/TCP endpoints | httpx / socket | None |
| DNS lookups | dnspython | None |
| Read service health API (if credential available) | httpx | None (read-only) |
| Read container environment variable names (not values) | Docker API | None |

**Tier 2: Research (autonomous, no approval)**

External information gathering to support investigation:

| Action | Method | Risk |
|--------|--------|------|
| Fetch GitHub release notes / changelog | HTTP GET (public repos) | None |
| Fetch Docker Hub image metadata | HTTP GET (public) | None |
| Search known issue trackers for error messages | Cloud LLM web research | None |
| Compare changelogs between old and new version | LLM analysis | None |
| Assess migration/schema change risk from changelog | LLM analysis | None |
| Query Operational Memory for past incidents | Local DB query | None |

**Tier 3: Remediation (requires user approval)**

System-modifying actions proposed after investigation:

| Action | Phase | Risk | Preflight checks |
|--------|-------|------|-----------------|
| Restart one named container | v1 | Low (reversible) | Container exists, is in failed/unhealthy state |
| Pull specific image tag (rollback) | v2 | Medium | No migrations between versions, old tag locally cached, changelog reviewed |
| Start/stop one named VM | v2 | Low | VM exists, state transition is valid |
| Modify config value (with backup) | v3 | Higher | Config backup taken, change is specific and bounded |

Every Tier 3 action includes:
- Evidence trail with structured evidence, inference, and recommendation
- Risk assessment with specific checks (migrations, schema changes, reversibility)
- User approval via notification channel
- Post-action verification ("did the fix work?")
- Audit log entry
- Operational Memory journal entry

### 5.6 Offline and Degraded-Mode Behavior

Kaval is designed to work fully offline with a local model. When internet access is unavailable, behavior degrades gracefully:

| Capability | Online | Offline |
|-----------|--------|---------|
| Layer 1: Deterministic monitoring | Full | Full (no dependency on internet) |
| Tier 1: Evidence gathering (logs, configs, probes) | Full | Full (all local) |
| Tier 2: Research (GitHub changelogs, Docker Hub) | Full | **Skipped** — investigation notes "research steps unavailable: no internet" |
| Tier 2: Operational Memory query | Full | Full (local DB) |
| Local SLM investigation | Full | Full (local model) |
| Cloud SOTA escalation | Available | **Unavailable** — investigation proceeds with local model only, confidence may be lower |
| Notifications (Telegram, ntfy) | Full | **Unavailable** — findings queued, delivered when connectivity returns |
| Risk assessment (changelog-based) | Full | **Degraded** — cannot verify migrations/schema changes from changelog, risk assessment notes "unable to verify: no internet" |

When Tier 2 research is skipped, the investigation explicitly reports it: "Research steps skipped (no internet access). Root cause analysis based on local evidence only. Confidence may be lower than usual." This prevents the user from thinking the investigation was thorough when it was operating in degraded mode.

---

## 6. Operational Memory

### 6.1 Overview

Operational Memory is Kaval's institutional knowledge system. It captures server-specific configuration, past incident history, and user-provided operational notes. Every investigation reads from Operational Memory, and every resolved incident writes to it. This creates a learning loop where the agent gets better at diagnosing your specific server over time.

### 6.2 Three Layers

**Layer 1: System Profile (auto-generated, auto-updated)**

Written by the auto-discovery engine. Updated on every discovery cycle. Contains factual system configuration that affects investigation.

```yaml
# Auto-generated — do not edit manually
# Last updated: 2026-03-30T14:00:00Z

system:
  hostname: ZacTower
  unraid_version: 7.2.1
  cpu: Intel i3-12100T
  memory_gb: 32
  gpu: NVIDIA (Plex transcoding + Windows VM passthrough)
  ups: APC Back-UPS (monitored via apcupsd)

storage:
  array:
    parity_drives: 1
    data_drives: 4
    cache: 2x NVMe RAID 1
    total_tb: 12
    used_tb: 4.2

networking:
  domain: zactower.com
  dns_provider: cloudflare
  reverse_proxy: nginx_proxy_manager
  tunnel: cloudflare_zero_trust
  vpn: wireguard
  dns_resolver: pihole
  ssl_strategy: cloudflare_origin_certs  # critical for TLS investigation

services:
  total_containers: 25
  total_vms: 3
  matched_descriptors: 22

vms:
  - name: Ubuntu Server
    purpose: Hosts Moodle LMS + MariaDB
    os: Ubuntu 22.04 LTS
    quirks: "LVM default partition is only ~10GB regardless of vdisk size"
  - name: Home Assistant
    purpose: Home automation (Ecobee, IoT)
    type: HAOS VM
  - name: Windows 11
    purpose: GPU passthrough workstation
    gpu_passthrough: true
```

**Why this matters:** When investigating a TLS failure, the agent immediately knows "this server uses Cloudflare origin certs, not Let's Encrypt" — which changes the entire investigation path. Without the system profile, it might waste time checking Let's Encrypt renewal status.

**Layer 2: Operational Journal (auto-written after investigations, user-editable)**

Every resolved incident produces a journal entry. This is the accumulated operational knowledge.

```yaml
journal:
  - id: inv-2026-03-15-001
    date: 2026-03-15
    incident_id: inc-2026-03-15-001
    services: [nginx-proxy-manager]
    summary: "NPM image auto-updated to v2.12.1, breaking TLS with Cloudflare origin certs"
    root_cause: "OpenSSL 3.5.5 in new Alpine base dropped cipher support needed for Cloudflare origin certs"
    resolution: "Pinned NPM to v2.12.0"
    time_to_resolution_minutes: 3
    model_used: cloud
    tags: [npm, tls, cloudflare, image-update, openssl]
    lesson: "NPM image updates should be tested before auto-applying. Consider disabling Watchtower for NPM."
    user_confirmed: true

  - id: inv-2026-03-01-001
    date: 2026-03-01
    incident_id: inc-2026-03-01-001
    services: [delugevpn, radarr, sonarr]
    summary: "VPN tunnel dropped after ISP IP change"
    root_cause: "ISP rotated public IP, VPN tunnel didn't reconnect"
    resolution: "Restarted DelugeVPN"
    recurrence_count: 3
    tags: [delugevpn, vpn, isp, recurring]
    lesson: "Recurring monthly issue. Restart always fixes. Consider health check auto-restart."
    user_confirmed: true

  - id: inv-2026-02-20-001
    date: 2026-02-20
    incident_id: inc-2026-02-20-001
    services: [ubuntu-server-vm, moodle]
    summary: "Moodle unreachable, VM disk full"
    root_cause: "Ubuntu LVM default partition only allocates ~10GB"
    resolution: "lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv && resize2fs /dev/..."
    tags: [vm, ubuntu, moodle, disk, lvm]
    lesson: "After any Ubuntu Server VM disk resize, must manually extend LVM partition."
    user_confirmed: true
```

**During investigation, the agent queries the journal:**
- "Has this service had incidents before?" → "Yes, NPM had a TLS breakage last month"
- "Is this a recurring issue?" → "DelugeVPN tunnel drops have happened 3 times. Restart always fixes it."
- "What's the resolution for this known issue?" → "Last time Moodle was unreachable, it was LVM partition full. Here's the exact command."

**Recurrence detection:** When the journal shows N occurrences of the same type of incident, the agent suggests a permanent fix: "This is your 4th DelugeVPN tunnel drop. Consider adding a health check that auto-restarts when tunnel drops, or switching to Gluetun."

**Layer 3: User Notes (manually written)**

The user provides operational knowledge the agent can't discover:

```yaml
notes:
  - service: plex
    note: "Plex Pass lifetime license. GPU transcoding enabled. If transcoding fails, check GPU Stats plugin."
    added: 2026-01-15

  - service: authentik
    note: "Google OAuth federated source configured. If SSO breaks after Google Cloud changes, check OAuth client ID in Authentik sources."
    added: 2026-02-01

  - service: networking
    note: "Router has crashed twice in the past year. If external access breaks but internal works, check router first."
    added: 2026-03-10

  - service: immich
    note: "Don't restart immich-ml during face recognition job. Migrated from Google Photos via immich-go."
    added: 2026-02-15
```

### 6.3 How Memory is Used in Investigation

When an investigation triggers, the LangGraph workflow includes a "query Operational Memory" step that pulls:

1. System profile context relevant to the failing domain (e.g., SSL strategy for TLS issues)
2. Journal entries for the affected services (past incidents and resolutions)
3. User notes for the affected services
4. Recurrence data (how many times has this type of failure happened?)

This context is included in the investigation prompt alongside findings, logs, and evidence.

### 6.4 Memory Trust Model

Operational Memory entries can become stale, wrong, or superseded. The investigation workflow applies trust filtering:

- **Confirmed entries** (user verified the root cause was correct) are preferred over speculative ones
- **Stale entries** (older than `stale_after_days` or not verified recently) are flagged: "this resolution worked 6 months ago but may be outdated"
- **Version-scoped entries** (`applies_to_version: "npm < 2.12.2"`) are only included when the current version matches
- **Superseded entries** are excluded from investigation context
- **Speculative entries** (auto-written without user confirmation) carry a disclaimer in investigation prompts
- **User notes with `safe_for_model: false`** are never included in LLM prompts

### 6.5 Memory Secret Redaction

Users will inevitably paste credentials, internal URLs, and sensitive commands into journal entries and user notes. Before any Operational Memory content is included in an LLM prompt, it passes through a redaction filter.

**Two redaction levels:**

| Level | When used | What is redacted |
|-------|-----------|-----------------|
| `redact_for_local` | Content sent to local model endpoint | API keys, tokens (Bearer/Basic/JWT), passwords, private key blocks, credentials in URLs |
| `redact_for_cloud` | Content sent to cloud model API | Everything in `redact_for_local` PLUS: internal IP addresses, hostnames, container names, internal URLs, unique service identifiers, Unraid share paths |

The distinction matters: internal hostnames and IP addresses are harmless for a local model running on the same server, but constitute operational intelligence that should not leave the network. Cloud model prompts get aggressively redacted; local model prompts get minimally redacted.

**Additional rules:**
- User notes with `safe_for_model: false` are excluded entirely from all LLM prompts (both local and cloud)
- Journal resolutions containing command-line credentials are redacted to structure only (command preserved, values replaced with `[REDACTED]`)
- YAML export of Operational Memory is treated as a sensitive artifact (the UI warns "this may contain operational details about your server")
- The redaction module (`src/kaval/memory/redaction.py`) is a required component, not optional. It runs on all memory content before prompt construction.

### 6.6 Storage

All three layers are stored in the SQLite database and exposed via the REST API and web UI. They are also exportable as YAML for backup, portability, or manual editing (with sensitivity warning).

---

## 7. Security Model

### 7.1 Hard Rules

- Kaval Core container runs as **non-root, unprivileged**
- **No docker.sock mount** on the Core container (Executor is the only container with docker.sock)
- **No broad host access**
- Core has **zero system-modification capability** — all mutations go through the Executor sidecar
- Executor sidecar has **no network access, no LLM access, no UI** — only a localhost API from Core
- Executor verifies HMAC-signed approval tokens before executing any action
- **Secrets never appear** in: LLM prompts (enforced by two-level redaction), investigation outputs, logs, git-tracked files, UI displays
- **All Tier 3 actions** require explicit user approval
- **Credentials are an event, not state** — volatile by default

### 7.2 Credential Model: UAC-Style Just-in-Time Access

**Install time:** Only Unraid API key required. This enables all Layer 1 monitoring and all Tier 1 evidence gathering.

**During investigation (Tier 1 + Tier 2):** The agent gathers evidence autonomously. Most evidence comes from Docker logs, container inspection, endpoint probes, and public resources (GitHub changelogs). No service API keys needed for most investigations.

**When deeper access would help:**

```
Kaval (via Telegram):
  "Radarr's container logs are vague. Its health diagnostics API
   would give me specific error details.

   I need the Radarr API key.
   (Find it: Settings → General → API Key in Radarr's web UI)

   [🔑 Enter key for this session only]
   [🔐 Store in vault (master password)]
   [⏭️ Skip — continue with logs only]"
```

**Three credential modes:**

| Mode | Storage | Lifetime | Risk |
|------|---------|----------|------|
| Volatile | In-memory only | 30 min default, auto-expires | Minimal — nothing persisted |
| Vault | Encrypted SQLite (Argon2id) | Until user deletes | Low — requires master password to unlock |
| Skip | None | N/A | Zero — investigation continues with lower confidence |

**Vault:** Encrypted with key derived from master passphrase. Auto-locks after 5 minutes. When locked, Kaval cannot access any stored credentials.

### 7.3 Action Safety

| Tier | Actions | Approval | Executor |
|------|---------|----------|----------|
| Tier 1: Evidence | Read logs, inspect configs, probe endpoints | None | Not needed (Core can do this) |
| Tier 2: Research | Fetch changelogs, search issues | None | Not needed (Core can do this) |
| Tier 3: Remediation | Restart container (v1), rollback image (v2), start/stop VM (v2) | Per-action user approval | Required (Executor sidecar) |

**v1 Executor allowlist:** `restart_container` only  
**Explicitly NOT allowed in any version:** delete containers/VMs/data, modify array, change DNS, modify firewall

### 7.4 Approval Token Contract

Every Tier 3 action request from Core to Executor includes an ApprovalToken. The Executor verifies the token before executing anything.

```python
class ApprovalToken(BaseModel):
    token_id: str                    # UUID, single-use
    incident_id: str                 # Bound to the specific incident
    action: str                      # "restart_container" — must match allowlist
    target: str                      # "delugevpn" — the specific target
    approved_by: str                 # "user_via_telegram" or "user_via_web"
    issued_at: datetime
    expires_at: datetime             # Default: 5 minutes after issuance
    nonce: str                       # Random, prevents replay
    hmac_signature: str              # HMAC-SHA256 over all fields above

    # Post-execution (filled by Executor)
    used_at: datetime | None         # Set on first use; token rejected if already set
    result: str | None               # "success" or "failed: <reason>"
```

**Token rules:**
- Single-use: once `used_at` is set, the token is permanently consumed
- Time-limited: rejected if `datetime.now() > expires_at`
- Incident-bound: the `incident_id` must match an open incident in Core's database
- Action-bound: the `action` and `target` must exactly match what was proposed
- HMAC-verified: signature checked by Executor using a shared secret (configured at deploy time via Docker secret)
- Non-replayable: `nonce` ensures each token is unique

### 7.5 Audit Trail

Every action is logged with: timestamp, action type, target, trigger (which investigation), approval details, credential used (reference only, not the secret), result, post-action verification, model used.

---

## 8. Integration Architecture

### 8.1 Inbound: Alert Sources

```
External tool → POST /api/v1/webhooks/{source} → Normalizer → Finding → Incident → Investigation
```

**Priority 1 (native):** Docker event stream, Unraid system notifications  
**Priority 2 (common):** Uptime Kuma, Grafana, Prometheus Alertmanager, Netdata  
**Priority 3 (community):** Zabbix, Checkmate, generic JSON webhook

### 8.2 Outbound: Exposing Data

**REST API** (`/api/v1/`): services, findings, incidents, investigations, graph, changes, actions, config  
**Prometheus metrics** (`/metrics`): service counts, finding counts, investigation counts, model usage, MTTR  
**Homepage/Homarr widget** (`/api/v1/widget`): compact health summary  
**WebSocket**: real-time UI updates

### 8.3 External API Integrations (investigation-time, UAC-gated)

| Service | What it provides | When used |
|---------|-----------------|-----------|
| Cloudflare | DNS records, proxy mode, tunnel status, SSL settings | TLS/DNS investigation |
| Authentik | Application/provider inventory, OIDC status | SSO investigation |
| Radarr/Sonarr/Prowlarr | Health diagnostics, queue status | ARR pipeline investigation |
| Plex | Active streams, transcode status | Media investigation |
| Home Assistant | Entity states, automation status | Automation investigation |
| GitHub API | Release notes, changelogs, known issues | Tier 2 research |
| Docker Hub API | Image metadata, vulnerability info | Tier 2 research |

All are optional and follow the UAC credential model.

---

## 9. UI/UX Design

### 9.1 Tech Stack

React 18+ / TypeScript / React Flow (dependency graph) / Tailwind CSS (dark theme) / Recharts (timelines) / WebSocket (real-time)

### 9.2 Primary Views

**1. Service Map (hero feature)**
Full-stack dependency graph with live health status. Nodes colored green/yellow/red. Dependency edges show confidence type. Click node → detail panel. Failure path highlights in red.

**2. Incidents Feed**
Active and recent incidents. Each incident card shows: severity, affected services, root cause summary, status (open/investigating/resolved), MTTR. Incidents group related findings — one card per root cause, not per finding.

**3. Investigation Detail**
Structured investigation report with three sections:
- **Evidence:** every evidence-gathering step listed with result
- **Inference:** root cause analysis with confidence level, research findings
- **Recommendation:** proposed action with risk assessment, approve/dismiss buttons
- Model used and cost displayed

**4. Change Timeline**
Horizontal timeline: image updates, restarts, Unraid events, plugin updates. Findings overlaid. Correlation highlights ("change event near finding = highlighted").

**5. Operational Memory**
System profile viewer. Journal browser (searchable by service, tag, date). User notes editor. Recurrence reports.

**6. Approval Queue**
Pending Tier 3 actions with evidence, risk assessment, approve/reject, expiry countdown.

**7. Settings**
Discovered services, dependency graph editor, notification channels, model config, credential vault management, check schedules, profile selection.

### 9.3 Notification UX

**Grouped per incident** (not per finding). One Telegram message per root cause:

```
🔴 Radarr and Sonarr failing

Root cause: DelugeVPN VPN tunnel dropped (14:23)
Confidence: High

Evidence:
• DelugeVPN logs: "VPN tunnel inactive"
• Radarr: "Download client not available"
• Sonarr: "Download client not available"
• Prowlarr: healthy ✅ (not the cause)

Impact: Download pipeline blocked. Playback unaffected.

Recommended: Restart DelugeVPN
Past history: This has happened 3 times. Restart resolved it each time.

[✅ Approve restart] [🔍 Full details] [❌ Dismiss]
```

---

## 10. Notification System

### 10.1 Library

Python `apprise` — single dependency, 80+ services.

**Priority 1:** Telegram (interactive with inline keyboards), ntfy, Discord, Email  
**Priority 2:** Slack, Teams, Pushover, Gotify, Matrix  
**Priority 3:** SMS/WhatsApp (Twilio), 60+ more via apprise

### 10.2 Policy

| Priority | Severity | Behavior |
|----------|----------|----------|
| P1 | Critical | Immediate push + approval task |
| P2 | High | Immediate with 15-min dedup |
| P3 | Medium | Hourly digest |
| P4 | Low | Dashboard only |

---

## 11. Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.12+ | All backend |
| Agent framework | LangGraph 1.0.x | Investigation workflow |
| LLM clients | langchain-openai (OpenAI-compatible), langchain-anthropic, langchain-google | Model-agnostic; local via any OpenAI-compatible server (Ollama, LM Studio, vLLM) |
| Web framework | FastAPI | REST API, WebSocket |
| Frontend | React 18+ / TypeScript | Dashboard |
| Graph viz | React Flow | Dependency map |
| Database | SQLite | All persistent data |
| Scheduler | APScheduler | Check scheduling |
| HTTP client | httpx | Probes, API calls |
| Notifications | apprise | 80+ notification channels |
| Schemas | Pydantic 2.x | All data models |
| Docker client | docker SDK 7.x | Container operations |
| Unraid client | unraid-api 1.6+ (PyPI) | Unraid GraphQL |
| DNS | dnspython | DNS checks |
| Encryption | cryptography (Fernet/Argon2) | Credential vault |
| Testing | pytest 8+ | All test layers |
| Linting | ruff | Code quality |
| Types | mypy | Static checking |

---

## 12. Data Models

### 12.1 Incident (NEW in v3)

```python
class Incident(BaseModel):
    id: str                          # UUID
    title: str                       # "Radarr and Sonarr failing — DelugeVPN tunnel down"
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "investigating", "awaiting_approval",
                    "remediating", "resolved", "dismissed"]
    trigger_findings: list[str]      # Finding IDs that created this incident
    all_findings: list[str]          # All findings grouped into this incident
    affected_services: list[str]     # Service IDs

    # Causal taxonomy — distinguishes symptom from cause from resolution
    triggering_symptom: str | None   # "Radarr health check failing"
    suspected_cause: str | None      # "DelugeVPN VPN tunnel inactive"
    confirmed_cause: str | None      # Set only when cause is verified (not just because fix worked)
    root_cause_service: str | None   # The service where the problem originates
    resolution_mechanism: str | None # "Restarted DelugeVPN container"
    cause_confirmation_source: Literal[
        "user_confirmed",            # User explicitly confirmed this was the real cause
        "resolution_inferred",       # Fix worked, but cause is inferred not proven
        "recurrence_pattern",        # Matched a known pattern from journal
        "unconfirmed"                # Investigation completed but cause not verified
    ] | None
    confidence: float                # 0.0-1.0

    investigation_id: str | None     # Linked investigation
    approved_actions: list[str]      # Action IDs approved for this incident
    changes_correlated: list[str]    # Change IDs potentially causal
    grouping_window_start: datetime  # When first finding fired
    grouping_window_end: datetime    # When grouping window closed
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    mttr_seconds: float | None       # Mean time to resolution
    journal_entry_id: str | None     # Operational Memory journal entry

class IncidentGroupingRule:
    """Findings are grouped into the same incident when:
    1. They share a common upstream dependency in the graph
    2. They fire within a configurable time window (default: 5 min)
    3. Their services are in the same dependency chain
    """
    window_minutes: int = 5
    group_by_dependency_chain: bool = True
    group_by_common_upstream: bool = True
```

### 12.2 Finding

```python
class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    domain: str                      # "arr", "networking", "unraid", etc.
    service_id: str
    summary: str
    evidence: list[Evidence]
    impact: str
    confidence: float
    status: Literal["new", "grouped", "investigating", "resolved", "dismissed", "stale"]
    incident_id: str | None          # Which incident this belongs to
    related_changes: list[Change]
    created_at: datetime
    resolved_at: datetime | None
```

### 12.3 Investigation

```python
class Investigation(BaseModel):
    id: str
    incident_id: str                 # Every investigation is for an incident
    trigger: Literal["auto", "webhook", "user_request"]
    status: Literal["running", "completed", "failed", "cancelled"]

    # Evidence chain (Tier 1)
    evidence_steps: list[EvidenceStep]  # Ordered list of what was checked

    # Research (Tier 2)
    research_steps: list[ResearchStep]  # Changelogs, known issues, etc.

    # Analysis
    root_cause: str | None
    confidence: float
    model_used: Literal["local", "cloud", "both", "none"]
    cloud_model_calls: int

    # Operational Memory context used
    journal_entries_referenced: list[str]
    user_notes_referenced: list[str]
    recurrence_count: int            # How many times this pattern seen before

    # Remediation proposal (Tier 3)
    remediation: RemediationProposal | None

    started_at: datetime
    completed_at: datetime | None

class EvidenceStep(BaseModel):
    """One step in the evidence gathering chain"""
    order: int
    action: str                      # "read_container_logs", "check_image_history"
    target: str                      # "nginx-proxy-manager"
    result_summary: str              # "SSL handshake failure in 47 of last 200 lines"
    result_data: dict | str          # Raw data (redacted of secrets)
    timestamp: datetime

class ResearchStep(BaseModel):
    """One step in the research chain"""
    order: int
    action: str                      # "fetch_github_changelog", "compare_versions"
    source: str                      # "github.com/jc21/nginx-proxy-manager/releases"
    result_summary: str
    timestamp: datetime

class RemediationProposal(BaseModel):
    action_type: str                 # "restart_container", "pull_image_tag"
    target: str
    rationale: str                   # Why this action should fix the issue
    risk_assessment: RiskAssessment
    status: Literal["proposed", "approved", "rejected", "executed", "verified"]

class RiskAssessment(BaseModel):
    overall_risk: Literal["low", "medium", "high"]
    checks: list[RiskCheck]          # Individual risk checks performed
    reversible: bool
    warnings: list[str]

class RiskCheck(BaseModel):
    check: str                       # "database_migrations"
    result: Literal["pass", "fail", "unknown"]
    detail: str                      # "No migrations between v2.12.0 and v2.12.1"
```

### 12.4 Service

```python
class Service(BaseModel):
    id: str
    name: str
    type: Literal["container", "vm", "plugin", "share", "system", "external", "network"]
    category: str
    status: Literal["healthy", "degraded", "down", "unknown", "stopped"]
    descriptor_id: str | None
    descriptor_source: Literal["shipped", "auto_generated", "user", None]
    container_id: str | None
    vm_id: str | None
    image: str | None
    endpoints: list[Endpoint]
    dependencies: list[DependencyEdge]
    dependents: list[str]
    last_check: datetime | None
    active_findings: int
    active_incidents: int

class DependencyEdge(BaseModel):
    target_service_id: str
    confidence: Literal["configured", "runtime_observed", "user_confirmed",
                        "inferred", "auto_generated"]
    source: str                      # "docker_network", "shared_volume", "descriptor", "user", "llm"
    description: str | None          # "Shared volume: media"
```

### 12.5 Change

```python
class Change(BaseModel):
    id: str
    type: Literal["image_update", "container_restart", "config_change",
                  "unraid_event", "plugin_update", "external_change"]
    service_id: str | None
    description: str
    old_value: str | None
    new_value: str | None
    timestamp: datetime
    correlated_incidents: list[str]  # Incidents this change may have caused
```

### 12.6 Operational Memory

```python
class SystemProfile(BaseModel):
    """Auto-generated, auto-updated"""
    hostname: str
    unraid_version: str
    hardware: HardwareProfile
    storage: StorageProfile
    networking: NetworkingProfile
    services_summary: ServicesSummary
    vms: list[VMProfile]
    last_updated: datetime

class JournalEntry(BaseModel):
    """Auto-written after incident resolution"""
    id: str
    incident_id: str
    date: date
    services: list[str]
    summary: str
    root_cause: str
    resolution: str
    time_to_resolution_minutes: float
    model_used: str
    tags: list[str]
    lesson: str
    recurrence_count: int

    # Trust model
    confidence: Literal["confirmed", "likely", "speculative"]
    user_confirmed: bool             # User verified this was the real cause
    last_verified_at: datetime | None # When last confirmed still relevant
    applies_to_version: str | None   # e.g., "npm < 2.12.2" — scopes relevance
    superseded_by: str | None        # ID of newer entry that replaces this
    stale_after_days: int | None     # Auto-mark as stale after N days

class UserNote(BaseModel):
    """Manually written by user"""
    id: str
    service_id: str | None           # None = general note
    note: str
    safe_for_model: bool = True      # False = never include in LLM prompts
    last_verified_at: datetime | None
    stale: bool = False              # User or system can mark as outdated
    added_at: datetime
    updated_at: datetime
```

---

## 13. Repository Structure

```
kaval/
├── src/
│   ├── kaval/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── models.py                    # All data models from Section 12
│   │   │
│   │   ├── discovery/
│   │   │   ├── engine.py                # Auto-discovery orchestrator
│   │   │   ├── unraid.py               # Unraid API discovery
│   │   │   ├── docker.py               # Docker container discovery
│   │   │   ├── matcher.py              # Service descriptor matching
│   │   │   └── dependency_mapper.py    # Dependency graph with edge confidence
│   │   │
│   │   ├── monitoring/
│   │   │   ├── scheduler.py
│   │   │   ├── checks/
│   │   │   │   ├── base.py
│   │   │   │   ├── container_health.py
│   │   │   │   ├── endpoint_probe.py
│   │   │   │   ├── tls_cert.py
│   │   │   │   ├── dns_resolution.py
│   │   │   │   ├── log_patterns.py
│   │   │   │   ├── unraid_system.py
│   │   │   │   ├── vm_health.py
│   │   │   │   ├── dependency_chain.py
│   │   │   │   ├── change_detection.py
│   │   │   │   └── plugin_health.py
│   │   │   └── change_tracker.py
│   │   │
│   │   ├── incidents/
│   │   │   ├── manager.py               # Incident creation, grouping, lifecycle
│   │   │   ├── grouping.py              # Finding → Incident grouping rules
│   │   │   └── resolution.py            # Resolution verification, MTTR
│   │   │
│   │   ├── investigation/
│   │   │   ├── workflow.py              # LangGraph investigation graph
│   │   │   ├── evidence.py              # Tier 1: evidence collection
│   │   │   ├── research.py             # Tier 2: changelog, known issues
│   │   │   ├── prompts.py              # Investigation prompt templates
│   │   │   ├── correlation.py          # Multi-finding correlation
│   │   │   ├── risk_assessment.py      # Tier 3: remediation risk checks
│   │   │   └── history.py              # Operational Memory query
│   │   │
│   │   ├── actions/
│   │   │   ├── executor_client.py       # Client to Executor sidecar API
│   │   │   ├── approvals.py
│   │   │   └── allowed_actions.py
│   │   │
│   │   ├── memory/
│   │   │   ├── system_profile.py        # Auto-generated system profile
│   │   │   ├── journal.py              # Investigation journal CRUD
│   │   │   ├── user_notes.py           # User notes CRUD
│   │   │   ├── recurrence.py           # Recurrence detection
│   │   │   └── redaction.py            # Secret pattern redaction before LLM prompts
│   │   │
│   │   ├── notifications/
│   │   │   ├── bus.py
│   │   │   ├── formatter.py
│   │   │   ├── channels.py
│   │   │   └── telegram_interactive.py
│   │   │
│   │   ├── credentials/
│   │   │   ├── vault.py
│   │   │   ├── volatile.py
│   │   │   └── access.py
│   │   │
│   │   ├── integrations/
│   │   │   ├── webhooks/
│   │   │   │   ├── receiver.py
│   │   │   │   └── normalizers/
│   │   │   │       ├── uptime_kuma.py
│   │   │   │       ├── grafana.py
│   │   │   │       ├── prometheus.py
│   │   │   │       └── generic.py
│   │   │   └── external_apis/
│   │   │       ├── cloudflare.py
│   │   │       ├── github_releases.py   # Changelog research
│   │   │       ├── dockerhub.py         # Image metadata research
│   │   │       ├── authentik.py
│   │   │       └── arr_api.py
│   │   │
│   │   ├── store/
│   │   │   ├── database.py
│   │   │   ├── findings.py
│   │   │   ├── incidents.py
│   │   │   ├── services.py
│   │   │   ├── investigations.py
│   │   │   ├── changes.py
│   │   │   ├── memory.py               # Operational Memory persistence
│   │   │   └── audit.py
│   │   │
│   │   ├── api/
│   │   │   ├── app.py
│   │   │   ├── routes/
│   │   │   │   ├── health.py
│   │   │   │   ├── services.py
│   │   │   │   ├── findings.py
│   │   │   │   ├── incidents.py
│   │   │   │   ├── investigations.py
│   │   │   │   ├── graph.py
│   │   │   │   ├── actions.py
│   │   │   │   ├── memory.py           # Operational Memory API
│   │   │   │   ├── webhooks.py
│   │   │   │   ├── metrics.py
│   │   │   │   ├── widget.py
│   │   │   │   └── config.py
│   │   │   └── websocket.py
│   │   │
│   │   └── cli/
│   │       └── main.py
│   │
│   ├── executor/                        # Separate container
│   │   ├── __init__.py
│   │   ├── server.py                    # Tiny FastAPI on localhost only
│   │   ├── allowlist.py                 # Strict action allowlist
│   │   ├── docker_actions.py            # restart_container, pull_image
│   │   └── vm_actions.py               # start_vm, stop_vm
│   │
│   └── web/                             # React frontend
│       ├── package.json
│       └── src/
│           ├── components/
│           │   ├── ServiceMap.tsx
│           │   ├── IncidentsFeed.tsx
│           │   ├── InvestigationDetail.tsx
│           │   ├── ChangeTimeline.tsx
│           │   ├── OperationalMemory.tsx
│           │   ├── ApprovalQueue.tsx
│           │   └── Settings/
│           └── ...
│
├── services/                            # Service descriptor library
│   ├── media/
│   ├── arr/
│   ├── downloads/
│   ├── networking/
│   ├── identity/
│   ├── cloud/
│   ├── automation/
│   ├── monitoring/
│   ├── databases/
│   ├── system/
│   └── auto_generated/
│
├── schemas/
│   ├── finding.json
│   ├── incident.json
│   ├── service_descriptor.json
│   ├── approval.json
│   ├── approval_token.json              # Core↔Executor token contract
│   ├── action_result.json
│   └── risk_assessment.json
│
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── scenario/
│   │   ├── test_npm_tls_breakage.py
│   │   ├── test_delugevpn_tunnel_drop.py
│   │   ├── test_container_crash_loop.py
│   │   ├── test_cert_expiry.py
│   │   ├── test_disk_prefail.py
│   │   ├── test_authentik_sso_failure.py
│   │   ├── test_cache_pool_full.py
│   │   ├── test_pihole_dns_failure.py
│   │   └── fixtures/
│   └── security/
│
├── docs/
│   ├── architecture.md
│   ├── getting-started.md
│   ├── configuration.md
│   ├── service-descriptor-authoring.md
│   ├── security-model.md
│   ├── operational-memory.md
│   ├── contributing.md
│   └── adr/
│       ├── 001-langgraph-over-ms-agent-framework.md
│       ├── 002-docker-not-plugin.md
│       ├── 003-two-layer-monitoring.md
│       ├── 004-dual-model-architecture.md
│       ├── 005-uac-credential-model.md
│       ├── 006-service-descriptors-not-code.md
│       ├── 007-no-uptime-kuma-fork.md
│       ├── 008-core-executor-split.md
│       ├── 009-incident-first-class-entity.md
│       ├── 010-three-tier-action-model.md
│       ├── 011-operational-memory.md
│       ├── 012-evidence-inference-recommendation-framing.md
│       └── 013-memory-trust-model-and-redaction.md
│
├── deploy/
│   ├── Dockerfile                       # Core container
│   ├── Dockerfile.executor              # Executor sidecar
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── unraid-ca-template.xml
│
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## 14. Testing Strategy

### 14.1 Test Layers

| Layer | What | Coverage target |
|-------|------|----------------|
| Unit | Checks, models, matchers, formatters, grouping | All business logic |
| Contract | All shipped descriptors valid, normalizers correct, API schemas | All shipped content |
| Integration | Unraid adapter, Docker adapter, Ollama, Executor sidecar | All adapters |
| Scenario | End-to-end incident narratives with fixtures | All major failure modes |
| Security | Secret redaction, credential isolation, Executor allowlist, action boundaries | All security surfaces |

### 14.2 Scenario Test Library

Every scenario test simulates a real incident:

1. **NPM TLS breakage:** Image update → OpenSSL change → TLS failure → changelog research → rollback proposal
2. **DelugeVPN tunnel drop:** VPN drops → Radarr + Sonarr fail → dependency walk → grouped incident → restart
3. **Cert expiry:** 7-day warning, 1-day critical threshold
4. **Disk pre-fail:** SMART warning → finding → alert
5. **Authentik down:** SSO failure → all protected services affected → dependency walk
6. **Cache pool full:** Docker appdata writes failing → multiple containers affected
7. **Pi-hole down:** DNS resolution failing → network-wide impact
8. **Container crash loop:** Restart storm detection → grouped findings → log analysis
9. **Recurrence detection:** DelugeVPN tunnel drop for the 4th time → journal reference → permanent fix suggestion

### 14.3 Operational Success Metrics

**CI-enforced quality gates (build fails if these fail):**

| Metric | Target | Enforcement |
|--------|--------|-------------|
| Scenario test pass rate | 100% | `pytest tests/scenario/` in CI pipeline |
| Descriptor contract test pass rate | 100% | `pytest tests/contract/` in CI pipeline |
| Secret redaction coverage | 100% | `pytest tests/security/` — no known secret patterns in prompt output |
| Type checking | Clean | `mypy` in CI pipeline |
| Linting | Clean | `ruff` in CI pipeline |

**Runtime operational SLOs (monitored in production, alerted if breached):**

| Metric | Target | How measured |
|--------|--------|-------------|
| Investigation latency (local SLM) | < 30 seconds | Timer from incident creation to investigation completion |
| Investigation latency (cloud) | < 60 seconds | Timer from incident creation to investigation completion |
| Action verification success | > 95% | Post-action health check confirms fix worked |
| Evidence coverage | > 90% investigations with 3+ evidence steps | Count evidence steps per investigation |
| Cloud model call rate | < 20/day | Counter, enforced by cost controls config |

**Product review metrics (human-evaluated periodically, guide feature priorities):**

| Metric | Target | How measured |
|--------|--------|-------------|
| False positive rate | < 5/day (normalized by service count) | Findings dismissed as noise / total findings, reviewed weekly |
| Incident grouping accuracy | > 80% | Periodic human review: did this incident correctly group related findings? |
| Root cause usefulness | > 70% user-confirmed | Incidents where `cause_confirmation_source = user_confirmed` |
| Recurrence detection accuracy | > 90% | Correctly matched repeat incident pattern to journal entry |
| MTTR improvement | Measurable reduction vs pre-Kaval | Tracked per-incident; compared to user-estimated manual time |

CI gates block merges. Runtime SLOs trigger alerts. Product metrics are reviewed in sprint retrospectives.

### 14.4 Definition of Done (per feature)

- [ ] Passes type checking (mypy) and linting (ruff)
- [ ] Unit tests covering business logic
- [ ] Contract tests (if schemas/descriptors involved)
- [ ] At least one scenario test (if domain feature)
- [ ] Feature documentation
- [ ] Configuration documented
- [ ] Security considerations reviewed (especially for actions/credentials)
- [ ] Failure modes and rollback documented
- [ ] Audit trail verified (if actions involved)
- [ ] Operational Memory impact documented (what gets written to journal)

---

## 15. Phased Delivery Plan

### Phase 0: Foundation (1-2 weeks)

**Objective:** Repo scaffold, all data models, CI, proof of life.

**Deliverables:**
- Repository structure
- All Pydantic models (Finding, Incident, Service, Investigation, Change, DependencyEdge, EvidenceStep, ResearchStep, RemediationProposal, RiskAssessment, ApprovalToken, SystemProfile, JournalEntry, UserNote)
- JSON schemas
- SQLite database with migrations
- CI pipeline (lint, type check, test)
- Dockerfile for Core + Executor
- ADR documents (all 13)
- Mock check → finding → incident → console output (proof of life)
- README with vision statement

**Tasks:** P0-01 through P0-09

| ID | Title | Outputs |
|----|-------|---------|
| P0-01 | Repo scaffold | Directory structure, pyproject.toml |
| P0-02 | Core data models | models.py: ALL models from Section 12 |
| P0-03 | SQLite database | database.py: tables, CRUD, migrations |
| P0-04 | JSON schemas | schemas/*.json |
| P0-05 | Incident grouping logic | grouping.py: finding → incident rules |
| P0-06 | Mock check + incident pipeline | Mock check → finding → incident → console |
| P0-07 | CI pipeline | .github/workflows/ci.yml (includes descriptor contract tests) |
| P0-08 | Docker setup | Dockerfile (Core), Dockerfile.executor, docker-compose |
| P0-09 | ADRs + README | 13 ADR files, README.md |

**Exit criteria:**
- `pytest` passes with at least one test per data model
- `docker compose up` starts Core and Executor containers
- Mock check produces a finding → incident stored in SQLite
- All 13 ADRs written and reviewed

**Frozen interface contracts (must be reviewed and stable before Phase 1 begins):**

These contracts are the foundation for parallel work in Phase 1+. Worker agents code against these interfaces. If a contract needs to change after freeze, it requires an ADR and lead architect approval.

1. **Core↔Executor API** — action request format, localhost endpoint, response schema
2. **ApprovalToken schema** — as defined in Section 7.4 (single-use, HMAC-signed, time-limited)
3. **Incident lifecycle state machine** — valid status transitions (open → investigating → awaiting_approval → remediating → resolved/dismissed)
4. **Investigation output schema** — EvidenceStep, ResearchStep, RemediationProposal, RiskAssessment structures
5. **Notification callback payloads** — finding/incident → formatter → channel adapter interface
6. **Operational Memory query/result schema** — journal query filters → filtered/redacted results

---

### Phase 1: Auto-Discovery + Deterministic Monitoring (3-4 weeks)

**Objective:** Kaval discovers everything and monitors it with zero additional configuration.

**Deliverables:**
- Auto-discovery engine (Unraid + Docker)
- Service descriptor matching + 15 shipped descriptors
- Dependency graph with edge confidence
- 12 deterministic checks
- Incident manager (grouping, lifecycle)
- Change detection + timeline
- System profile (Operational Memory Layer 1)
- FastAPI with core endpoints
- CLI (kaval status, kaval findings, kaval incidents)
- Basic web UI with service map + incidents feed

**Checks:**
1. Container health (running/stopped/unhealthy/restarting)
2. Restart storm detection
3. Endpoint HTTP/HTTPS probe
4. TLS certificate validity + expiry
5. DNS resolution accuracy
6. Unraid array health
7. Unraid disk SMART warnings
8. Share capacity + growth
9. Cache pool status
10. VM state + hosted service reachability
11. Log error pattern detection (from descriptors)
12. Docker image change detection
13. Dependency chain validation

**Exit criteria:**
- Fresh install auto-discovers 20+ containers on real Unraid server
- Service map shows services with dependency edges (with confidence)
- Checks run on schedule and produce findings grouped into incidents
- System profile written to Operational Memory
- Change timeline tracks image updates + restarts
- Visible in web UI and CLI

**Tasks:** P1-01 through P1-22

| ID | Title | Deps |
|----|-------|------|
| P1-01 | Unraid API discovery | P0-02 |
| P1-02 | Docker API discovery | P0-02 |
| P1-03 | Service descriptor schema + loader | P0-04 |
| P1-04 | Write 15 service descriptors | P1-03 |
| P1-05 | Dependency graph with edge confidence | P1-03 |
| P1-06 | Check framework + scheduler | P0-06 |
| P1-07 | Container health check | P1-06, P1-02 |
| P1-08 | Restart storm detection | P1-07 |
| P1-09 | Endpoint probe check | P1-06 |
| P1-10 | TLS cert check | P1-06 |
| P1-11 | DNS resolution check | P1-06 |
| P1-12 | Unraid system checks | P1-06, P1-01 |
| P1-13 | VM health check | P1-06, P1-01 |
| P1-14 | Log pattern check | P1-06, P1-03 |
| P1-15 | Change detection + tracker | P1-02 |
| P1-16 | Dependency chain check | P1-05 |
| P1-17 | Incident manager | P0-05, P1-05 |
| P1-18 | System profile (Operational Memory) | P1-01, P1-02 |
| P1-19 | FastAPI application | P1-17 |
| P1-20 | CLI | P1-17 |
| P1-21 | React service map UI | P1-19 |
| P1-22 | WebSocket real-time updates | P1-19 |

---

### Phase 2A: Investigation Engine + Notifications + Restart (3-4 weeks)

**Objective:** When something breaks, Kaval investigates using evidence gathering (Tier 1), notifies with structured evidence/inference/recommendation, and can restart containers with approval.

**Deliverables:**
- LangGraph investigation workflow (Tier 1 evidence gathering)
- Local model integration (OpenAI-compatible endpoint, e.g., Ollama)
- Investigation prompt templates
- Notification bus (apprise)
- Telegram interactive handler (inline keyboards)
- Notification grouping per incident
- Executor sidecar (restart-container only)
- Basic investigation detail view in UI
- 3+ scenario tests with fixtures (DelugeVPN, cert expiry, crash loop)

**Exit criteria:**
- Container failure → incident → investigation → Telegram message with evidence + inference + recommendation
- Investigation includes: log analysis, dependency check, change correlation
- User approves restart via Telegram → Executor restarts container → verification
- DelugeVPN, cert expiry, and crash loop scenario tests pass

**Tasks:** P2A-01 through P2A-14

| ID | Title | Deps |
|----|-------|------|
| P2A-01 | Evidence collection module (Tier 1) | P1-02, P1-14, P1-15 |
| P2A-02 | Investigation prompt templates | P2A-01 |
| P2A-03 | LangGraph investigation workflow (Tier 1) | P2A-01, P2A-02 |
| P2A-04 | Local model integration (OpenAI-compatible) | P2A-03 |
| P2A-05 | Notification bus (apprise) | P1-17 |
| P2A-06 | Notification formatter | P2A-05 |
| P2A-07 | Incident-grouped notifications | P2A-05, P1-17 |
| P2A-08 | Telegram interactive handler | P2A-05 |
| P2A-09 | Executor sidecar | P0-08 |
| P2A-10 | Executor client in Core | P2A-09 |
| P2A-11 | Scenario: DelugeVPN tunnel drop | P2A-03 |
| P2A-12 | Scenario: Cert expiry | P2A-03 |
| P2A-13 | Scenario: Container crash loop | P2A-03 |
| P2A-14 | UI: Basic investigation detail | P2A-03, P1-21 |

---

### Phase 2B: Research + Credentials + Memory + Polish (2-3 weeks)

**Objective:** Enrich investigations with changelog research, credential-gated API access, and Operational Memory learning loop.

**Deliverables:**
- Tier 2 research: GitHub releases API, Docker Hub API, changelog comparison
- Cloud LLM integration (optional) + escalation policy
- Risk assessment engine (for future rollback capability)
- Credential request flow (UAC via Telegram)
- Credential vault (encrypted SQLite)
- Operational Memory journal (auto-written after resolution)
- Memory trust model + secret redaction
- Recurrence detection
- Change timeline view in UI
- Approval queue in UI
- Operational Memory browser in UI
- 2+ additional scenario tests (NPM TLS as research example, Authentik SSO)

**Exit criteria:**
- Investigation can fetch changelogs and identify breaking changes
- Cloud model invoked when local confidence is low (if configured)
- Credential request via Telegram works for volatile and vault modes
- Resolved incidents auto-write journal entries
- Recurrence detection: "this has happened N times, consider permanent fix"
- Journal entries include trust fields (confidence, staleness)
- Secret redaction passes security tests
- All scenario tests pass

**Tasks:** P2B-01 through P2B-14

| ID | Title | Deps |
|----|-------|------|
| P2B-01 | GitHub releases API client | — |
| P2B-02 | Docker Hub API client | — |
| P2B-03 | Research module (Tier 2) | P2B-01, P2B-02 |
| P2B-04 | Extend LangGraph workflow with Tier 2 | P2A-03, P2B-03 |
| P2B-05 | Cloud LLM integration + escalation policy | P2A-04 |
| P2B-06 | Risk assessment engine | P2B-03 |
| P2B-07 | Credential request flow (UAC) | P2A-08 |
| P2B-08 | Credential vault | P2B-07 |
| P2B-09 | Operational Memory journal + trust model | P1-18, P2A-03 |
| P2B-10 | Memory secret redaction module | P2B-09 |
| P2B-11 | Recurrence detection | P2B-09 |
| P2B-12 | Scenario: NPM TLS breakage (with Tier 2 research) | P2B-04 |
| P2B-13 | Scenario: Authentik SSO failure | P2A-03 |
| P2B-14 | UI: Change timeline, approval queue, memory browser | P2B-09, P1-21 |

---

### Phase 3: Webhook Integration + Operational Memory UX + Polish (2-3 weeks)

**Objective:** Kaval integrates with existing monitoring tools, Operational Memory is user-editable, and the product is ready for early adopters.

**Deliverables:**
- Webhook receiver + normalizers (Uptime Kuma, Grafana, Prometheus, Netdata)
- Prometheus /metrics endpoint
- User notes (Operational Memory Layer 3) via UI and Telegram
- Operational Memory browser UI (journal, notes, system profile)
- Recurrence reports and permanent-fix suggestions
- Homepage/Homarr widget API
- External API integrations (Cloudflare, Authentik — investigation-time, UAC)
- 15+ additional service descriptors
- Settings/configuration UI
- Audit trail UI
- Model usage / cost dashboard
- Auto-generated descriptor support (with quarantine rules)

---

### Phase 4: OSS Distribution (2 weeks)

**Deliverables:**
- Unraid Community Apps template
- Complete documentation
- Contributor guides (descriptors, normalizers)
- 30+ additional descriptors
- Security audit
- Performance optimization
- README with screenshots, demo, feature list

**Exit criteria:**
- New user installs → provides API key → sees service map in 2 minutes
- Contributor adds descriptor without touching Python
- No secrets in logs/prompts/UI

---

### Phase 5+ (Future)

- Image rollback (Tier 3 action with preflight checks + risk assessment)
- Start/stop VM actions
- Broader external API integrations
- MCP server exposure
- Multi-server support
- Proxmox support
- A2A protocol for multi-server agent coordination
- Mobile app / PWA

---

## 16. Agentic Coding Operating Model

### 16.1 Task Template

```
Task ID: P2A-03
Task Title: LangGraph investigation workflow (Tier 1)
Bounded Objective: Implement the investigation graph that collects
  evidence (Tier 1), queries Operational Memory, correlates findings
  with dependency graph and change timeline, and produces structured
  output: evidence list, inference (root cause + confidence), and
  remediation recommendation.

Inputs / Referenced Contracts:
  - models.py (Investigation, EvidenceStep, RemediationProposal, RiskAssessment)
  - evidence.py (Tier 1 evidence collection)
  - memory/journal.py (Operational Memory queries)

Files Allowed to Change:
  - src/kaval/investigation/workflow.py
  - tests/unit/test_investigation/test_workflow.py
  - tests/scenario/test_delugevpn_tunnel_drop.py

Files Forbidden to Change:
  - models.py, evidence.py (dependencies)

Required Tests:
  - Unit: single-finding investigation produces evidence steps
  - Unit: multi-finding investigation triggers dependency walk
  - Unit: operational memory journal entries included in context
  - Unit: recurrence count populated from journal
  - Scenario: DelugeVPN tunnel drop end-to-end

Acceptance Criteria:
  - Workflow produces Investigation with ordered EvidenceSteps
  - Output structured as evidence + inference + recommendation
  - RemediationProposal includes RiskAssessment
  - Recurrence count populated from Operational Memory
  - All tests pass
```

### 16.2 Agent Roles

| Agent | Owns | Does NOT own |
|-------|------|-------------|
| Lead architect | Schemas, ADRs, contracts, merge review | Individual feature code |
| Backend workers (parallel) | Individual checks, adapters, normalizers | Core models, database schema |
| Investigation agent | Workflow, evidence, research, prompts | Executor, notifications |
| Memory agent | System profile, journal, user notes, recurrence | Investigation workflow |
| Descriptor squad | YAML files, contract tests | Core code |
| UI agent | React components (consumes frozen API contracts) | Backend logic |
| Executor agent | Sidecar implementation, allowlist | Core container code |
| Test agent | Scenario harnesses, fixtures, regression tests | Feature code |
| Security reviewer | Credential isolation, secret redaction, action boundaries | Feature code |

### 16.3 Parallel Execution Rules

- Phase 0: sequential (foundation must be stable)
- Phase 1 checks (P1-07 through P1-16): parallel after P1-06
- Phase 1 UI (P1-21, P1-22): parallel with backend checks
- Phase 2A notification (P2A-05 through P2A-08): parallel with investigation (P2A-01 through P2A-04)
- Phase 2A Executor (P2A-09, P2A-10): parallel with investigation
- Phase 2B research (P2B-01 through P2B-06): parallel with credentials (P2B-07, P2B-08) and memory (P2B-09 through P2B-11)
- Schema review gate before any parallel work
- Security review for: credentials, Executor, actions, LLM prompts, memory redaction

### 16.4 ADR Governance

Architecture Decision Records are the mechanism for tracking significant design changes as the project evolves.

- **ADRs are immutable.** You never edit the content of an accepted ADR. When a decision is superseded, write a new ADR explaining the new decision and update the old ADR's status line to "Superseded by ADR-XXX."
- **The PRD is a living document.** `docs/prd.md` in the repo always reflects current architecture. When a significant change is made, the PRD section is updated AND an ADR explains why.
- **CHANGELOG.md** tracks what changed when, in Keep a Changelog format. Maintained as a convention, not a CI gate.
- **Contract tests for service descriptors** are CI-enforced. Every shipped descriptor must pass schema validation on every build.

| Artifact | Mutability | Purpose |
|----------|-----------|---------|
| PRD (`docs/prd.md`) | Edited to reflect current state | "How it works now" |
| ADRs (`docs/adr/`) | Immutable (only status line changes) | "Why we decided this" |
| CHANGELOG.md | Append-only | "What changed when" |

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| Finding | A detected condition (e.g., "container unhealthy") — the atomic unit of monitoring |
| Incident | A group of related findings with a shared root cause — the unit of investigation and notification |
| Investigation | AI-powered analysis of an incident producing three outputs: evidence, inference, recommendation |
| Evidence | Facts collected during investigation (log excerpts, container state, endpoint responses) |
| Inference | Conclusions drawn from evidence (root cause identification with confidence level) |
| Recommendation | Proposed action with risk assessment (the only part requiring user approval) |
| Evidence Step | One read-only action in the investigation (e.g., "read container logs") |
| Research Step | One information-gathering action (e.g., "fetch GitHub changelog") |
| Remediation Proposal | A proposed system-modifying action with risk assessment |
| Approval Token | Single-use, HMAC-signed, time-limited token authorizing the Executor to perform one action |
| Service Descriptor | YAML file describing a service's health endpoints, log patterns, dependencies |
| Dependency Edge | A directed connection between services with confidence type (configured/inferred/user-confirmed/auto-generated) |
| Operational Memory | System profile + investigation journal + user notes — the agent's institutional knowledge |
| UAC Model | Credentials requested per-use with explicit user consent |
| SLM | Small Language Model — local model via any OpenAI-compatible endpoint (7-8B parameters) |
| SOTA | State-of-the-Art cloud model (Claude, GPT, Gemini) for complex analysis |
| Core | Main Kaval container (unprivileged, no docker.sock, no system-modify capability) |
| Executor | Sidecar container with docker.sock and bounded action allowlist |

## Appendix B: Configuration Reference

```yaml
# kaval.yaml

server:
  host: 0.0.0.0
  port: 9800

unraid:
  api_url: http://localhost/graphql
  # api_key: from KAVAL_UNRAID_API_KEY env or Docker secret

models:
  local:
    provider: openai_compatible      # Works with Ollama, LM Studio, vLLM, LocalAI, etc.
    model: qwen3:8b
    base_url: http://localhost:11434/v1  # Ollama default; adjust for your provider
    api_key: "not-needed"            # Some providers require a dummy key
  cloud:                             # Optional — everything works without this
    provider: anthropic              # or: openai, google, openai_compatible (for OpenRouter)
    model: claude-sonnet-4-20250514
    api_key_env: KAVAL_CLOUD_API_KEY
    # For OpenRouter (multi-model, some free tiers):
    # provider: openai_compatible
    # base_url: https://openrouter.ai/api/v1
    # model: google/gemini-2.0-flash
    # api_key_env: KAVAL_OPENROUTER_KEY
  escalation:
    use_cloud_when:
      - finding_count > 3
      - multiple_domains_affected
      - local_confidence < 0.6
      - changelog_research_needed
      - user_requests_deep_analysis
  cost_controls:
    max_cloud_calls_per_day: 20
    max_cloud_calls_per_incident: 3

monitoring:
  check_interval_seconds: 300
  endpoint_probe_interval: 120
  cert_check_interval: 21600
  unraid_system_interval: 600
  log_scan_interval: 300

incidents:
  grouping_window_minutes: 5
  group_by_dependency_chain: true
  group_by_common_upstream: true

notifications:
  channels:
    - type: telegram
      bot_token_env: KAVAL_TELEGRAM_BOT_TOKEN
      chat_id_env: KAVAL_TELEGRAM_CHAT_ID
    - type: ntfy
      url: https://ntfy.sh/my-kaval-alerts
  policy:
    critical: immediate
    high: immediate_with_dedup
    medium: hourly_digest
    low: dashboard_only
  grouping:
    per_incident: true
    dedup_window_minutes: 15

profile: monitor  # monitor | assist | operate

vault:
  enabled: false
  auto_lock_minutes: 5

executor:
  enabled: false  # requires Executor sidecar container
  url: http://kaval-executor:9801

memory:
  journal_retention_days: 365
  journal_stale_after_days: 180      # auto-flag entries older than this as potentially stale
  profile_refresh_interval: 3600
  redaction_enabled: true            # always redact secrets before LLM prompts

services:
  descriptor_paths:
    - /app/services
    - /app/data/custom_services
    - /app/data/auto_generated
  auto_generate_descriptors: true
  auto_generate_quarantine: true  # enforce quarantine rules

integrations:
  webhooks:
    enabled: true
    normalizers: [uptime_kuma, grafana, prometheus, netdata, generic]
```
