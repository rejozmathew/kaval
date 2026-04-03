# Kaval — Phase 3/4 Product Requirements Expansion

**Date:** April 2, 2026  
**Author:** Rejo Z. Mathew  
**Baseline:** PRD v4.1 + CR-0001 + CR-0002 / ADR-014  
**Scope:** Everything Kaval needs beyond Phase 2B to become a complete, usable, distributable product  
**Status:** Draft for review

---

## 1. Purpose

Phase 2B delivered the core investigation loop: auto-discovery, deterministic monitoring, AI investigation with evidence/inference/recommendation, approval-gated restart, credentials/vault, operational memory with trust model, recurrence detection, and the initial UI surfaces.

This document captures everything else Kaval needs — not organized by "what fits in a phase" but by "what makes the product genuinely useful, trustworthy, and adoptable." Phasing and task breakdown follow from requirements, not the reverse.

---

## 2. Service Insight Model

### 2.1 Problem

Kaval currently understands services from the outside: Docker state, logs, endpoint probes, descriptor-matched patterns. For many services, much richer truth exists inside the service itself — proxy host lists in NPM, download client bindings in Radarr, OIDC provider health in Authentik, DNS upstream config in Pi-hole.

Users have no visibility into how deeply Kaval understands each service, what it's guessing about, or what they could do to improve that understanding.

### 2.2 Service Insight Levels

Every service in Kaval should have an explicit, visible insight level:

| Level | Name | Source | What Kaval knows |
|-------|------|--------|-----------------|
| 0 | Discovered | Docker API only | Container exists, running state, ports, networks, image |
| 1 | Matched | Docker + shipped descriptor | Health endpoints, log patterns, dependency hints, common failure modes |
| 2 | Monitored | Level 1 + deterministic checks running | Active health status, cert validity, DNS, restart patterns, log errors |
| 3 | Investigation-ready | Level 2 + LLM endpoint available | Can produce evidence/inference/recommendation when something breaks |
| 4 | Deep-inspected | Level 3 + service API access configured | Can query service internals: proxy hosts, client bindings, provider health, config state |
| 5 | Operator-enriched | Level 4 + user notes, confirmed edges, tuned thresholds | Full operational context including human knowledge |

All levels describe **current capability**, not event history. A service at Level 3 is investigation-ready whether or not it has ever been investigated. A service at Level 4 has a working deep inspection adapter, whether or not an incident has ever triggered deep evidence gathering for it.

### 2.3 Insight Level Display

In the service map, on the service detail panel, and in the first-run setup:

- Each service shows its current insight level (icon + label)
- Services below their maximum achievable level show an "improve" affordance
- Clicking "improve" shows exactly what's needed: "Provide Radarr API key to enable deep inspection" or "Confirm this dependency edge to improve investigation accuracy"
- A global "Kaval Effectiveness" summary shows: X services at full insight, Y services could be improved, Z services are unknown

### 2.4 Descriptor Capability Declaration

The service descriptor schema should be extended to declare what deeper inspection is possible:

```yaml
# Extension to existing descriptor format
inspection:
  surfaces:
    - id: health_api
      type: api
      description: "Radarr health diagnostics"
      endpoint: /api/v3/health
      auth: api_key
      auth_header: X-Api-Key
      read_only: true
      facts_provided:
        - health_issues
        - download_client_status
        - indexer_status
      confidence_effect: "Upgrades dependency edges to runtime_observed"
      version_range: ">=3.0"

    - id: system_status
      type: api
      description: "Radarr system status and version"
      endpoint: /api/v3/system/status
      auth: api_key
      auth_header: X-Api-Key
      read_only: true
      facts_provided:
        - version
        - runtime_info
        - startup_path

  credential_hints:
    api_key:
      description: "Radarr API Key"
      location: "Radarr Web UI → Settings → General → API Key"
      prompt: "For deeper investigation of download client and indexer health, provide your Radarr API key."
```

The key principle: **descriptors declare what's possible. Adapter code performs extraction. The LLM never drives the inspection — it reads the structured results.**

---

## 3. Deep Service Inspection

### 3.1 Architecture

Deep inspection is a lightweight built-in adapter model — not a general-purpose external plugin platform, but an explicit internal interface with typed contracts, health states, and degradation rules.

It extends the existing architecture naturally:

- **Descriptors** declare available inspection surfaces (Section 2.4)
- **Adapter code** performs the actual extraction, parsing, retries, health checks, and degradation handling
- **Evidence gathering** (Tier 1 in the investigation workflow) invokes adapters when credentials are available
- **The credential vault / UAC flow** handles authentication
- **Structured facts** are returned and stored — the LLM reasons over them but never drives the API calls
- **Confidence levels** on dependency edges upgrade from `inferred` to `runtime_observed` when service APIs confirm relationships

**The descriptor / adapter responsibility split is a hard rule:**

| Belongs in descriptor | Belongs in adapter code |
|----------------------|------------------------|
| Surface exists (yes/no) | HTTP client logic |
| Surface type (api/config/db) | Request construction, parsing, retries |
| Auth mode (api_key/token/basic) | Session management, token refresh |
| Facts available (list of fact names) | Extraction logic, field mapping |
| Confidence effect | Health check implementation |
| Version compatibility range | Version detection and compatibility logic |
| User-facing prompt text | Error handling, degradation, fallback |

Descriptors must never contain procedural logic: no selectors, no navigation flows, no scraping steps, no endpoint-specific parsing instructions. If you're writing "how to extract" rather than "what can be extracted," it belongs in adapter code.

```
Investigation triggers
  → Evidence gathering step: "query Radarr health API"
  → Adapter code: GET /api/v3/health with stored API key
  → Structured result: {download_clients: [{name: "DelugeVPN", status: "connected"}]}
  → Edge confidence upgrade: Radarr→DelugeVPN goes from "inferred" to "runtime_observed"
  → LLM receives structured facts alongside logs and other evidence
```

### 3.2 Adapter Implementation Pattern

Each deep inspection adapter is a Python module that:

1. Declares which descriptor surface IDs it handles
2. Accepts credentials from the vault/UAC system
3. Makes read-only API calls to the service
4. Returns typed, structured facts (Pydantic models)
5. Reports its own health (connection succeeded, auth valid, response parseable)
6. Declares version compatibility
7. Gracefully degrades (returns empty facts with a reason, never crashes)

```python
class ServiceAdapter(Protocol):
    """Common interface for deep service inspection adapters."""

    adapter_id: str                        # "radarr_api"
    surface_ids: list[str]                 # ["health_api", "system_status"]
    supported_versions: str | None         # ">=3.0"
    read_only: bool                        # Always True for v1

    async def inspect(
        self,
        service: Service,
        credentials: dict[str, str],
    ) -> AdapterResult:
        """
        Perform read-only inspection. Returns structured facts.
        Never raises — returns AdapterResult with status and reason on failure.
        """
        ...

class AdapterResult(BaseModel):
    adapter_id: str
    status: Literal["success", "auth_failed", "connection_failed",
                    "version_incompatible", "parse_error", "degraded"]
    facts: dict[str, Any]                  # Structured facts extracted
    edges_discovered: list[DiscoveredEdge] # Dependency edges found
    timestamp: datetime
    reason: str | None                     # Explanation if status != success
```

### 3.3 Priority Adapters (v1)

Build deep inspection adapters for the services where the investigation value is highest and the API is stable:

| Service | API type | What deep inspection reveals | Investigation value |
|---------|----------|----------------------------|-------------------|
| **Nginx Proxy Manager** | REST API (port 81) | Proxy hosts, domains, upstream targets, cert bindings, access lists | Critical — reverse proxy is the ingress layer for all external access |
| **Radarr / Sonarr** | REST API (/api/v3/) | Download client bindings, indexer status, queue health, root folders | High — the ARR pipeline is one of the most common failure chains |
| **Prowlarr** | REST API (/api/v1/) | Indexer health, app sync status, connected apps | High — indexer problems cascade to all ARR apps |
| **Authentik** | REST API (/api/v3/) | Applications, providers, outposts, OIDC status | High — identity failures affect all SSO-protected services |
| **Pi-hole** | REST API (/admin/api.php) | Upstream DNS servers, blocklist status, query stats, DHCP config | Medium — DNS failures have network-wide impact |
| **Cloudflare** | Public API (api.cloudflare.com) | Zone records, proxy mode, tunnel routes, SSL mode, origin cert status | High — external access depends on Cloudflare config |
| **Uptime Kuma** | REST API or WebSocket | Monitored targets, alert routing, current status | Medium — enriches Kaval's external view with existing monitoring data |
| **Home Assistant** | REST API (/api/) | Integration health, entity states, automation status, add-on state | Medium — HA is a common homelab control plane |
| **Nextcloud** | OCS API (/ocs/v2.php/) | Trusted domains, DB/cache backend health, maintenance mode, storage | Medium — Nextcloud failures often trace to DB/Redis dependencies |
| **Plex** | REST API (port 32400) | Active sessions, transcode status, library scan state, GPU usage | Lower — Plex problems are usually resource-related |
| **MariaDB / PostgreSQL** | Direct connection or health endpoint | Connection count, replication status, slow queries, database sizes | Lower — database health is already partially visible from dependent services |

### 3.4 Non-API Services and Fallback

For services without a usable API (or where the user hasn't provided credentials):

- Kaval continues with Level 0-3 capabilities (Docker inference + descriptor + checks + investigation)
- The UI clearly shows "deep inspection available but not configured" or "no deep inspection available for this service"
- For services with only a WebUI management portal and no structured API, Kaval does NOT attempt to scrape or automate the portal
- Instead, Kaval can offer guided fact-collection: "I can't automatically inspect this service. Here are the things that would help me investigate problems — you can add them as notes: [checklist of useful facts]"

### 3.5 Facts Imported from Deep Inspection

Structured facts from adapters are:

- Stored in the database with timestamp and adapter version
- Available to the investigation workflow during evidence gathering
- Used to upgrade dependency edge confidence
- Displayed in the service detail UI panel
- Refreshed periodically on a per-adapter cadence (NOT every check cycle — adapters have their own schedule):
  - **Default background refresh:** every 30-60 minutes for most API-based adapters
  - **Faster refresh during active incidents:** when an incident involves an adapter-equipped service, refresh on investigation trigger
  - **Rate-limit aware:** respect external API rate limits (especially Cloudflare, which has strict per-minute limits)
  - **Configurable per adapter:** user can adjust refresh interval in settings
- Subject to two-level redaction (local-safe vs cloud-safe) before LLM prompt inclusion
- Never used for action recommendations from auto-generated descriptors (quarantine rule still applies)

---

## 4. Kaval Capability Health and Self-Diagnostics

### 4.1 Problem

Once Kaval has deep inspection for even a few services, two different things can break:

1. The user's service is broken (Kaval's core job to detect and investigate)
2. Kaval's own ability to do its job is broken (degraded capability)

These must be distinguishable. This applies not just to deep inspection adapters but to every capability layer Kaval provides.

### 4.2 Kaval Capability Health Model

Kaval should continuously monitor and expose the health of its own systems:

| Capability layer | Healthy state | Degraded state | User impact |
|-----------------|---------------|----------------|-------------|
| **Discovery pipeline** | Unraid API + Docker API reachable, discovery running on schedule | API unreachable, stale discovery data | Service map may be outdated |
| **Check scheduler** | All checks running on their configured intervals | Scheduler stalled, checks overdue | Findings delayed or missing |
| **Local model** | Model endpoint reachable, responding within latency target | Endpoint unreachable or slow | Investigation unavailable or degraded |
| **Cloud model** | API key valid, endpoint reachable (if configured) | Auth failed, endpoint unreachable, budget exhausted | Cloud escalation unavailable |
| **Notification channels** | All configured channels deliverable | Channel delivery failing (Telegram bot blocked, ntfy unreachable) | User won't receive alerts |
| **Credential vault** | Vault accessible, master key available | Vault locked, credentials inaccessible | Deep inspection and UAC flows unavailable |
| **Deep inspection adapters** | Per-adapter: connected, authenticated, returning valid facts | Per-adapter: auth failed, version drift, parse error | Service insight level degrades |
| **Webhook receiver** | Endpoints listening, normalizers healthy | Normalizer throwing errors, source auth failing | External alerts not ingested |
| **Executor process** | Socket listener running, docker.sock accessible | Process down, socket unreachable | Remediation actions unavailable |
| **Database** | SQLite healthy, migrations current, size within limits | Database locked, corruption detected, disk full | State loss or degraded persistence |

### 4.3 Kaval Health Dashboard

A dedicated "Kaval Health" section in the UI (and optionally in the widget API) showing:

- Overall Kaval status: healthy / degraded / critical
- Per-capability status with explanation for any non-healthy state
- Actionable guidance for each degradation: "Local model is unreachable — check that Ollama is running on port 11434"
- History: when did capability X last change state?

### 4.4 Deep Inspection Adapter Health (specific detail)

Each adapter maintains a health status:

| Status | Meaning | User-visible behavior |
|--------|---------|----------------------|
| `healthy` | Adapter connected, authenticated, returning valid facts | Green indicator on service detail |
| `auth_failed` | Credentials rejected or expired | Prompt to re-authenticate |
| `connection_failed` | Service API unreachable (service may be down, or endpoint changed) | Distinguish from service-down finding if possible |
| `version_incompatible` | Service version outside adapter's supported range | "NPM updated to v3.0 — deep inspection adapter needs update" |
| `parse_error` | API responded but output doesn't match expected schema | "Deep inspection degraded — API response format may have changed" |
| `degraded` | Partial facts extracted, some surfaces failed | Show what's working and what isn't |
| `disabled` | User explicitly disabled this adapter | No indicator — user chose this |
| `unconfigured` | Adapter available but no credentials provided | "Configure credentials for deeper inspection" |

### 4.5 Adapter Self-Diagnostic Checks

Kaval should periodically validate its own adapters:

- **Connection test:** Can the adapter reach the service's management API?
- **Auth test:** Are stored credentials still accepted?
- **Schema test:** Does the API response still match the expected format?
- **Version check:** Is the service version still within the adapter's supported range?

These checks run on a slower schedule than monitoring checks (e.g., every 30 minutes or on each investigation trigger). They produce internal health events, not findings — adapter health problems are Kaval's problem, not the user's.

### 4.6 Adapter Degradation Behavior

When an adapter degrades:

1. Kaval falls back to base inference (Level 0-3) for that service
2. Investigation confidence for that service may be lower — the investigation output says "deep inspection unavailable for NPM; analysis based on logs and endpoints only"
3. The service detail UI shows adapter status with explanation
4. A notification is sent (once, not repeatedly) if the user has opted into Kaval self-health notifications
5. Dependency edges that were at `runtime_observed` confidence (from the adapter) revert to `inferred` or `configured` after a staleness period

### 4.7 Adapter Update Strategy

When a service updates and an adapter breaks:

- Kaval detects the version change (already part of change detection)
- Kaval tests the adapter against the new version
- If the adapter breaks, it reports `version_incompatible` or `parse_error`
- The service map and service detail show "deep inspection needs update"
- Community/contributor PRs can update adapter logic and supported version ranges
- This is the primary maintenance mechanism — version-aware adapters with graceful degradation, not silent breakage

---

## 5. First-Hour Experience

### 5.1 Problem

A new user installs Kaval, provides their Unraid API key, and sees... a service map with colored dots. They don't know:

- Are the inferred dependency edges correct?
- What is Kaval actually monitoring?
- What would make Kaval more effective?
- Why should they trust the investigation output?
- What should they configure next?

If nothing is broken, the product feels inert. If something IS broken but the investigation is generic, the product feels like it wasted their time.

### 5.2 Guided Setup Flow

After initial discovery, Kaval should present a guided setup experience:

**Step 1: Discovery Summary**
- "I found 25 containers, 3 VMs, 8 shares"
- "I matched 22 containers to known services"
- "3 containers are unknown — I can try to identify them, or you can tell me what they are"
- For each unknown container: show image name, ports, volumes — ask user to identify or skip

**Step 2: Dependency Review**
- Show the inferred dependency graph
- Highlight edges that are low-confidence: "I think Radarr depends on DelugeVPN because they share the downloads network. Is that correct?"
- Let the user confirm, correct, or add edges with simple click interactions
- Show which edges are confident (Docker network links) vs guesses (descriptor hints)

**Step 3: Effectiveness Assessment**
- Per-service insight level summary
- "12 services at full monitoring capability"
- "5 services could be improved with API credentials" (list them with one-click "configure" buttons)
- "3 services are unknown — generic monitoring only"
- "2 services have deep inspection adapters available but unconfigured"

**Step 4: Notification Setup**
- "How do you want to be notified?" (Telegram, ntfy, Discord, email, etc.)
- Quick-test: send a test notification to verify the channel works
- Severity preferences: what should generate immediate alerts vs dashboard-only

**Step 5: Model Configuration**
- "Do you have a local model running?" (auto-detect Ollama/LM Studio)
- If yes: "Investigation and root-cause analysis enabled"
- If no: "Kaval will monitor and alert, but won't investigate root causes automatically. Set up Ollama for AI-powered investigation."
- Optional: cloud model for complex investigations

### 5.3 Ongoing Effectiveness Dashboard

Not just during setup — always accessible from the main UI:

- **Kaval Effectiveness Score:** computed as: (number of services at their maximum achievable insight level) / (total services) × 100. All services weighted equally in v1. A service's "maximum achievable" level is determined by what's possible given its descriptor and available adapters — an unknown container's max is Level 0 (Discovered), a matched service without an adapter's max is Level 3 (Investigation-ready), a service with an available adapter's max is Level 4 or 5.
- **Improvement suggestions:** ordered by impact. Impact is estimated by: number of downstream dependents affected × insight gap. ("Configuring the NPM API adapter would improve investigation for 8 services that depend on your reverse proxy" ranks higher than "Confirm this edge for a standalone service.")
- **Recent insight upgrades:** "Last week you confirmed 3 dependency edges — investigation confidence improved for the ARR pipeline"
- **Missing descriptors:** "3 containers have no matching descriptor — contribute one or request one"

### 5.4 Healthy-State Value

When nothing is broken, Kaval should still be useful:

- **Service map** as a live infrastructure diagram (this already exists)
- **Change timeline** showing what changed recently (image updates, restarts, config changes)
- **System health summary** with trends (disk growth, cert expiry approaching, resource usage patterns)
- **Operational memory** as a searchable knowledge base of past incidents and lessons
- **"What would happen if..."** scenario mode (future): "What services would be affected if Pi-hole went down?"

---

## 6. Interactive Dependency Graph

### 6.1 Current State

The dependency graph exists as a React Flow visualization with health-colored nodes and directed edges. It shows the topology but is largely read-only and doesn't expose confidence, insight depth, or missing information.

### 6.2 Required Enhancements

**Edge confidence visualization:**
- Different edge styles for each confidence type: solid (user-confirmed), dashed (configured/observed), dotted (inferred), faint dotted (auto-generated)
- Hover on edge: shows source of truth ("Inferred from Radarr descriptor: typical_dependencies includes download client") and confidence level
- Click on edge: panel with confirm/edit/remove options

**Node insight depth:**
- Each node shows an insight level indicator (icon or ring color)
- Nodes below max level have a subtle "improve" badge
- Click node: service detail panel with insight level, adapter status, configuration options, active findings, recent incidents

**Missing information indicators:**
- Edges that would benefit from confirmation show a "?" icon
- Nodes with unconfigured deep inspection show a "configure" icon
- Unknown containers show a "identify" icon
- All of these are clickable and lead to actionable flows

**Graph editing:**
- Click empty space between two nodes → "Add dependency" flow
- Right-click edge → confirm / remove / change direction
- Drag to rearrange layout (already in React Flow)
- "Auto-layout" button to reset to algorithmic layout
- "Show only affected" filter during incident investigation (highlight the failure path, fade everything else)

**Graph filters and views:**
- Filter by service category (media, networking, identity, etc.)
- Filter by health status (show only unhealthy/degraded)
- Filter by insight level (show only services needing improvement)
- Filter by confidence (show only low-confidence edges)
- Toggle labels: service names, ports, edge descriptions

---

## 7. Admin UX and Service Management

### 7.1 Design Principle

Kaval's complexity must be managed through simplicity in the interface. Every configuration surface should follow a principle: **show what Kaval knows, suggest what it needs, make it easy to provide.**

**Access model:** v1 assumes a single trusted local admin. There is no multi-user authentication or role-based access control. Anyone who can access the Kaval web UI on port 9800 has full admin access. Multi-user RBAC is out of scope for v1 and would require an explicit future CR/ADR if needed.

### 7.2 Service Detail Panel

For each service, a comprehensive panel accessible from the service map or a services list view:

**Identity section:**
- Service name, matched descriptor, Docker image, container ID
- Descriptor source: shipped / auto-generated / user-created
- Edit descriptor match if wrong ("This is actually Sonarr, not Radarr")

**Health section:**
- Current status with active findings
- Check results: last run time, interval, status per check type
- Per-check suppression toggle: "This check produces false positives — suppress it"
- Threshold adjustment where applicable: "Alert me about cert expiry at 14 days instead of 7"

**Insight section:**
- Current insight level with explanation
- Available but unconfigured surfaces (with "configure" button)
- Adapter health status for configured surfaces
- Imported facts from deep inspection (structured display, not raw JSON)
- Last inspection timestamp and next scheduled

**Dependencies section:**
- Upstream and downstream dependencies with confidence types
- "Add dependency" button
- Per-edge confirm/edit/remove
- "What depends on this service?" impact view

**Credentials section:**
- Which credentials are configured (vault / volatile / none)
- "Update credentials" button
- "Test connection" button
- Credential usage log (when was it last used, for what)

**Memory section:**
- User notes for this service
- Past incidents from journal
- Recurrence patterns
- "Add note" inline

**Notifications section:**
- Per-service notification override (suppress all, custom severity threshold, custom channel)

### 7.3 Descriptor Editor

For users who want to customize or create descriptors:

**View mode:**
- Rendered view of the descriptor (not raw YAML) showing: match patterns, endpoints, log signals, dependencies, failure modes, investigation context, inspection surfaces
- "This descriptor is shipped with Kaval" / "This is a user-customized descriptor" / "This was auto-generated — review needed"

**Edit mode:**
- Form-based editing for common fields (match patterns, endpoints, dependencies)
- YAML editor for advanced users
- Validation on save (schema check, policy lint)
- Preview: "With these changes, Kaval would match X containers and infer Y dependencies"

**Auto-generated descriptor review:**
- Queue of auto-generated descriptors awaiting review
- Side-by-side: "Here's what the LLM generated" vs "Here's what the container actually looks like"
- Promote (moves to user descriptors), edit-then-promote, or dismiss
- Promoted descriptors get full monitoring; dismissed ones stay at generic Level 0

### 7.4 Settings Management

**Model configuration:**
- Local model endpoint URL, model name, test connection
- Cloud model provider, API key (stored in vault), test connection
- Escalation policy: when to use cloud (adjustable thresholds)
- Cost controls: max calls per day / per incident
- Model usage dashboard: calls made today, cost estimate, breakdown by investigation

**Notification configuration:**
- Channel management: add/remove/test notification channels
- Per-severity routing: which channels get which severity levels
- Dedup settings: window size, grouping behavior
- Quiet hours: suppress non-critical notifications during specified windows
- Kaval self-health notifications: opt in/out for adapter degradation, check failures, etc.

**Monitoring configuration:**
- Global check intervals (adjustable)
- Per-check enable/disable
- Per-service check overrides
- False positive feedback: "Mark this finding as noise" → adjusts future behavior
- Maintenance mode: temporarily suppress findings for a service during planned work

**Credential vault:**
- List of stored credentials (names/services only, never values)
- Per-credential: last used, last tested, expiry if known
- "Test all credentials" button
- Vault lock/unlock status
- Master password change

**System:**
- Database size and maintenance
- Log level configuration
- Backup/export (operational memory, settings, descriptors — with sensitivity warnings)
- Import (descriptors, notes, configuration from backup)
- About page: version, build info, uptime, model status

### 7.5 Proactive Suggestions

The admin interface should actively suggest improvements:

- "You have 3 services without descriptors — Kaval can try to generate them"
- "Authentik's API key hasn't been tested in 30 days — would you like to verify?"
- "Your investigation model is local-only. For complex multi-service issues, consider adding a cloud model."
- "DelugeVPN has had 6 tunnel drops in the past month. Consider switching to Gluetun or adding a health-check restart."
- "This check has been producing false positives — consider adjusting the threshold or suppressing it."

These suggestions appear in a dedicated "Recommendations" section of the dashboard or as non-intrusive inline hints in relevant UI areas.

---

## 8. Webhook Ingestion

### 8.1 Purpose

Kaval should not compete with Uptime Kuma, Grafana, or Prometheus — it should sit on top of them as the investigation and reasoning layer. Webhook ingestion makes this possible: existing monitoring tools send their alerts to Kaval, and Kaval investigates the root cause.

### 8.2 Normalized Event Schema

All incoming webhooks are normalized to a common internal event:

```python
class WebhookEvent(BaseModel):
    id: str                              # UUID, generated on receipt
    source: str                          # "uptime_kuma", "grafana", "prometheus", etc.
    source_event_id: str | None          # Original event ID from source (for dedup)
    received_at: datetime
    service_hint: str | None             # Service name/identifier from the webhook
    matched_service_id: str | None       # Kaval service ID after matching
    severity: Literal["critical", "high", "medium", "low", "info", "resolved"]
    title: str
    body: str                            # Original alert text/description
    url: str | None                      # Link back to source (Uptime Kuma status page, Grafana panel, etc.)
    tags: dict[str, str]                 # Preserved labels/tags from source
    raw_payload: dict                    # Original webhook body, stored for debugging
    status: Literal["new", "matched", "finding_created", "duplicate", "ignored"]
```

### 8.3 Ingestion Pipeline

```
POST /api/v1/webhooks/{source}
  → Auth check (per-source API key)
  → Source-specific normalizer → WebhookEvent
  → Dedup check (source + source_event_id within window)
  → Service matching (service_hint → Kaval service)
  → Finding creation (if new and matches a service)
  → Finding enters normal incident grouping pipeline
  → Investigation triggers if appropriate
```

### 8.4 Source-Specific Normalizers

Each source gets a normalizer that translates its native webhook payload into WebhookEvent:

| Source | Webhook format | Key fields to extract |
|--------|---------------|----------------------|
| **Uptime Kuma** | JSON POST | monitor name, status, tags, heartbeat data |
| **Grafana** | JSON POST (Grafana alerting format) | alert name, state, labels, dashboard URL |
| **Prometheus Alertmanager** | JSON POST (Alertmanager webhook format) | alert name, status, labels, annotations, generator URL |
| **Netdata** | JSON POST | alarm name, chart, status, info |
| **Generic JSON** | Configurable JSON POST | User-defined field mappings |

### 8.5 Authentication

Each webhook source is configured with its own API key:

```yaml
webhooks:
  sources:
    - id: uptime_kuma
      api_key_env: KAVAL_WEBHOOK_KEY_UPTIMEKUMA
      enabled: true
    - id: grafana
      api_key: "generated-random-key-here"
      enabled: true
```

Webhook endpoints require `Authorization: Bearer <api_key>` header authentication. Query-string authentication (`?key=<api_key>`) is supported as a **compatibility fallback only** for monitoring tools that cannot set custom headers — it should not be the recommended method because keys in URLs leak through logs, browser history, and shared links. Keys are generated by Kaval and displayed in the settings UI for the user to copy into their monitoring tool's webhook configuration.

### 8.6 Service Matching

When a webhook arrives, Kaval tries to match it to an existing service:

1. **Exact match:** webhook includes a service name or container name that matches a Kaval service
2. **Tag match:** webhook labels/tags include a hostname, port, or URL that matches a known endpoint
3. **Fuzzy match:** webhook title/body contains a service name
4. **Unmatched:** webhook creates a finding against a generic "external alert" pseudo-service
5. **Multi-service alerts:** some Prometheus/Grafana alerts cover a group or shared resource, not a single service. Kaval should attempt to match against multiple services and create a finding that references the alert group rather than forcing a single-service match.

Unmatched webhooks are still visible in the UI and can be manually linked to services.

### 8.7 Deduplication and Resolution

- Duplicate detection: same source + same source_event_id within a configurable window (default: 15 minutes)
- Resolution events: when a source sends a "resolved" status, Kaval updates the corresponding finding
- Flapping detection: if a source sends repeated up/down/up/down within a window, Kaval consolidates rather than creating many findings

### 8.8 Webhook Security and Data Governance

- **Raw payload retention:** `raw_payload` is stored for debugging but is subject to a retention policy (default: 30 days). Raw payloads are purged after the retention window unless the associated incident is still open.
- **Raw payload redaction:** before storage, raw payloads pass through the same secret-pattern redaction used elsewhere (API keys, tokens, passwords in URLs). This prevents monitoring tools from accidentally forwarding secrets into Kaval's database.
- **Raw payload export:** when exporting webhook data (via API or backup), raw payloads are included only if the user explicitly opts in. The export warns about potential sensitive content.
- **Rate limiting:** the webhook endpoint enforces a per-source rate limit (default: 60 events per minute per source). Excess events are dropped with a 429 response and logged. This prevents a misconfigured monitoring tool from flooding Kaval.
- **Payload size limit:** individual webhook payloads are capped (default: 256 KB). Oversized payloads are rejected with a 413 response.
- **Replay protection:** if a source_event_id has been seen within the dedup window, the duplicate is acknowledged (200 response) but not processed. This prevents webhook retry behavior from creating duplicate findings.

---

## 9. Prometheus Metrics Endpoint

### 9.1 Endpoint

`GET /metrics` — standard Prometheus exposition format.

### 9.2 Metrics

**Service metrics:**
- `kaval_services_total{status}` — count by health status
- `kaval_services_insight_level{level}` — count by insight level
- `kaval_findings_active_total{severity}` — active findings by severity
- `kaval_incidents_active_total{status}` — active incidents by status

**Investigation metrics:**
- `kaval_investigations_total{status,model}` — investigations by status and model used
- `kaval_investigation_duration_seconds{model}` — histogram of investigation durations
- `kaval_investigation_cloud_calls_total` — cloud model calls counter
- `kaval_investigation_cloud_cost_estimate` — estimated cost (from token counts)

**Adapter metrics:**
- `kaval_adapters_total{status}` — adapter count by health status
- `kaval_adapter_inspections_total{adapter,status}` — inspection results by adapter

**Action metrics:**
- `kaval_actions_total{type,result}` — actions by type and result
- `kaval_approval_tokens_total{status}` — token lifecycle counts

**Webhook metrics:**
- `kaval_webhooks_received_total{source}` — incoming webhooks by source
- `kaval_webhooks_matched_total{source}` — successfully matched to services
- `kaval_webhooks_duplicate_total{source}` — deduplication counts

**System metrics:**
- `kaval_check_executions_total{check}` — check runs by type
- `kaval_check_duration_seconds{check}` — check execution time
- `kaval_database_size_bytes` — SQLite database size
- `kaval_uptime_seconds` — Kaval uptime

### 9.3 Security

The /metrics endpoint should be configurable:

- Enabled/disabled in config
- Optional auth (API key or basic auth)
- Configurable bind address (can be restricted to localhost if Prometheus is on the same host)

---

## 10. User-Facing Operational Memory

### 10.1 Current State

Phase 2B built the backend: system profile (auto-generated), investigation journal (auto-written with trust model), user notes (basic CRUD), redaction, recurrence detection. What's missing is the full user-facing experience.

### 10.2 User Notes Lifecycle

**Creation:**
- Via web UI: inline on service detail panel, or dedicated notes editor
- Via Telegram: reply to a Kaval message with "note:" prefix, or use /note command
- Via API: POST /api/v1/memory/notes

**Editing and management:**
- Edit in place in the UI
- Version history (simple: store previous versions, show diff)
- Archive (soft-delete: note is hidden from active views but retained in DB)
- Delete (hard-delete: user explicitly removes)
- Bulk operations: "archive all notes for this service"

**Trust and safety:**
- `safe_for_model` flag (default true, user can set false)
- Notes with `safe_for_model: false` never enter LLM prompts
- Notes undergo redaction before LLM prompt inclusion (same two-level redaction as journal entries)
- Stale detection: notes older than configurable threshold get a "may be outdated" flag
- UI shows which notes were used in recent investigations (transparency)

### 10.3 Memory Browser

A dedicated UI view for exploring all operational memory:

**Journal tab:**
- Searchable list of past incidents and their journal entries
- Filter by service, tag, date range, confidence level, confirmation status
- Each entry shows: summary, root cause, resolution, confidence, whether user-confirmed
- **Provenance indicator:** each entry clearly shows its source — auto-written from investigation, user-edited, imported from adapter, or inferred from recurrence pattern
- Click to see the full investigation that produced the entry
- "This entry is outdated" / "This entry was superseded" visual indicators
- Entries used in recent investigations are highlighted: "Referenced in investigation on March 28"

**Notes tab:**
- All user notes, grouped by service
- Global notes (not service-specific) shown separately
- **Provenance indicator per note:** user-created, auto-suggested, imported
- **Trust indicators:** safe_for_model status, stale flag, last verified date
- Quick-add note from this view
- Search across all notes

**System Profile tab:**
- Current auto-generated system profile
- Last updated timestamp
- Diff from previous version (what changed since last discovery cycle)
- User annotations on system profile entries ("this is important because...")

**Recurrence tab:**
- Services with recurring incident patterns
- Recurrence count, frequency, past resolutions
- Permanent-fix suggestions (generated from recurrence data + journal entries)
- "I implemented the fix" button → marks the recurrence pattern as addressed
- "Remind me later" → snooze the suggestion

**Facts tab (new — from deep inspection):**
- Structured facts imported from deep inspection adapters, per service
- Last refresh timestamp, adapter version, staleness indicator
- "These facts were used in the last investigation for this service"
- Read-only display (facts are managed by adapters, not user-editable)

### 10.4 Telegram Memory Interactions

Extend the Telegram interactive handler for memory operations:

- `/note <service> <text>` — add a note
- `/notes <service>` — list recent notes for a service
- `/journal <service>` — show recent journal entries for a service
- `/recurrence` — show active recurrence patterns
- Reply to an incident notification with a note → note is attached to that incident's service

---

## 11. Noise Control and Trust

### 11.1 Problem

False positives kill trust faster than missed detections. If a user gets 10 irrelevant notifications on day one, they'll disable notifications entirely. Kaval must give users granular control over what generates alerts and what doesn't.

### 11.2 Per-Service Check Suppression

In the service detail panel:

- Toggle each check type on/off for that service
- "This service intentionally has no TLS cert — suppress TLS check"
- "This container is supposed to be stopped — suppress container health check"
- Suppressions are stored as user preferences, not modifications to descriptors

### 11.3 Per-Check Threshold Adjustment

Where checks have configurable thresholds:

- Cert expiry warning threshold: default 7 days, adjustable per service
- Restart storm threshold: default 3 restarts in 10 minutes, adjustable
- Log error scan sensitivity: adjustable per service
- Endpoint probe timeout: adjustable per service

### 11.4 Finding Feedback Loop

When a user sees a finding and it's not useful:

- "Dismiss as false positive" → finding is dismissed, Kaval learns this pattern
- After N dismissals of the same type for the same service, Kaval suggests suppression: "You've dismissed 5 endpoint probe findings for this service — would you like to suppress this check?"
- Dismissal reasons: "false positive", "expected behavior", "not important", "already aware"
- Dismissal data is stored and visible in the audit trail

### 11.5 Maintenance Mode

When the user is doing planned work:

- Per-service maintenance mode: "I'm working on NPM — suppress findings for 2 hours"
- Global maintenance mode: "I'm rebooting the server — suppress everything for 30 minutes"
- Timer-based: auto-exits maintenance mode after the specified duration
- Visual indicator in UI and notifications: "This service is in maintenance mode"

### 11.6 Investigation Quality Controls

- If the local model produces a generic/unhelpful investigation ("the container may have crashed due to various reasons"), Kaval should detect this and either: escalate to cloud model (if configured), or flag the investigation as low-quality rather than presenting it confidently
- Investigation quality heuristic: does the investigation reference specific evidence? Does it name specific root causes? Does it differentiate between affected services and root cause services?
- User feedback on investigations: "This investigation was helpful" / "This investigation was not useful" → feeds into model/prompt improvement

### 11.7 Noise Control Guardrails

- **No auto-suppression of critical checks** without explicit user confirmation. Recurring dismissals suggest suppression — they never silently apply it.
- **Maintenance mode must be visibly active and time-bound.** The UI and notifications show "maintenance mode active, expires in 45 minutes." There is no indefinite maintenance mode — the user must set a duration.
- **Suppression history is visible** in the audit trail and service detail panel. If a check was suppressed, anyone can see when, by whom, and why.
- **Dismissed findings are reviewable.** A "Recently dismissed" section in the findings view lets users reconsider if they suppressed too aggressively.

---

## 12. Action Boundary (Phase 3/4)

### 12.1 Principle

Phase 3 and 4 introduce significant new capabilities: deep inspection adapters, external API integrations (Cloudflare, Authentik), webhook ingestion, admin UI, settings management, descriptor editing. None of these expand Kaval's system-modifying action scope.

### 12.2 Rules

- **All deep inspection adapters are read-only.** No adapter may create, modify, or delete any resource in the target service. This is enforced by the adapter interface contract (`read_only: bool = True`).
- **All external API integrations are read-only.** Cloudflare, Authentik, and any future integration fetch data for investigation purposes only.
- **The v1 Executor allowlist remains `restart_container` only.** No additional action types are added in Phase 3 or 4.
- **Descriptor editing and settings changes are admin operations, not LLM-driven.** The LLM cannot modify descriptors, settings, or credentials. These are user-initiated operations through the admin UI.
- **Webhook ingestion is inbound-only.** Kaval receives alerts; it does not push back to monitoring tools or modify their configuration.
- **Any future broadening of the action boundary requires an explicit CR and ADR** documenting the new action type, its risk assessment, approval model, and testing requirements.

### 12.3 Why This Matters

The combination of deep service access, external API credentials, and an admin UI creates a surface where it's tempting to add "helpful" write actions: "auto-fix the DNS record," "restart the Authentik outpost," "update the Cloudflare SSL mode." Every one of these would require extending the Executor allowlist, defining new approval flows, and assessing new risk profiles. That work is legitimate but it is explicitly future scope, not Phase 3/4.

---

## 13. Monitoring Cadence and Operational Model

### 13.1 Core Principle

Kaval is an always-on monitor, not a daily batch scanner. Each check type runs continuously on its own interval. The scheduler runs checks whenever they become due based on their configured frequency.

### 13.2 Check Cadence Defaults

| Check type | Default interval | Rationale |
|-----------|-----------------|-----------|
| Container health | 60 seconds | Fast detection of crashes and restart storms |
| Endpoint probe | 120 seconds | Balance between responsiveness and target load |
| TLS certificate | 6 hours | Certs change slowly; daily is sufficient but 6h catches expiry approaching |
| DNS resolution | 300 seconds | DNS changes are infrequent but impactful |
| Unraid system health | 600 seconds | Array/disk/cache status changes slowly |
| Log pattern scan | 300 seconds | Balance between log freshness and processing cost |
| Change detection | 300 seconds | Image updates, restart count changes |
| Dependency chain validation | 600 seconds | Derived from other checks; doesn't need to be faster |
| Plugin health | 3600 seconds | Plugins change very rarely |

### 13.3 Incident-Triggered Acceleration

When an incident is created, checks related to the affected services and their dependencies run at an accelerated interval (e.g., 30 seconds) until the incident is resolved or the acceleration window expires (default: 15 minutes). This enables faster evidence gathering and post-fix verification.

### 13.4 Topology and Discovery Refresh

The service map and dependency graph are refreshed through a combination of:

- **Scheduled full rediscovery:** every 5-10 minutes, Kaval re-queries the Unraid API and Docker API for the full service inventory. New containers, removed containers, and changed configuration are detected.
- **Event-driven refresh:** Docker events (container start/stop/restart/die) trigger immediate service state updates without waiting for the next scheduled cycle.
- **Change-triggered edge recalculation:** when a service's state changes, dependency edges involving that service are re-evaluated.

### 13.5 Deep Inspection Adapter Cadence

Adapter-based fact refresh runs on a separate, slower schedule:

- **Default background refresh:** 30-60 minutes per adapter (configurable)
- **Investigation-triggered refresh:** when an incident involves an adapter-equipped service, facts are refreshed immediately
- **Rate-limit awareness:** external APIs (especially Cloudflare) have strict rate limits; adapter cadence must respect them
- **Staleness threshold:** if adapter facts are older than 2x the refresh interval, they are marked as potentially stale in the UI and investigation prompts

### 13.6 Configurability

All cadence values are configurable:

- **Global defaults** in kaval.yaml / settings UI
- **Per-check overrides** in settings UI ("run TLS checks every 1 hour instead of 6")
- **Per-service overrides** in service detail panel ("check this specific service more/less frequently")
- **Per-adapter overrides** in adapter settings ("refresh Cloudflare facts every 15 minutes")

---

## 14. Service Lifecycle Events

### 14.1 Purpose

Services are not static. Containers are installed, updated, removed, and replaced. Kaval must define explicit behavior for each lifecycle state transition so that users trust the service map, history, and notifications.

### 14.2 Lifecycle Events and Behavior

| Event | Map behavior | History | Notifications | Dependencies | Incidents |
|-------|-------------|---------|---------------|-------------|-----------|
| **service_added** | New node appears immediately | Added to change timeline | Low: "Kaval discovered new container: Sonarr" (dashboard or digest) | Inferred edges created from descriptor + Docker topology | No incident unless already failing |
| **service_updated** | Node stays, metadata refreshed | Image change / config change recorded in timeline | If associated with a failure: part of incident notification. Otherwise: change event only. | Edges re-evaluated (new version may change capabilities) | If update causes failure: change-correlated incident |
| **service_restarted** | Node stays, restart count updated | Restart recorded in timeline | Only if restart storm threshold hit, or if part of an active incident | No change to edges | Restart storm finding if applicable |
| **service_removed_intentionally** | Node removed from active map. Appears in "Recently removed" for 7 days. | All history preserved: incidents, journal, notes, audit trail | Low: "Container removed: Sonarr" (dashboard only). Not treated as a failure. | Edges from this service removed. Downstream services re-evaluated: "DelugeVPN was removed — Radarr may lose download client" | If downstream services start failing: incident references the removal as likely cause |
| **service_removed_unexpectedly** | Node shows "missing" state (red/warning) | Recorded as unexpected removal in timeline | High: "Container unexpectedly disappeared: Sonarr. Was it intentionally removed?" with confirm/acknowledge buttons | Same as intentional, but treated with higher urgency in investigation | If downstream services fail: grouped incident with the disappearance as suspected root cause |
| **service_removed_during_maintenance** | Node removed quietly | Recorded in timeline with "during maintenance" tag | Suppressed (maintenance mode active) | Edges removed, downstream re-evaluation suppressed during maintenance window | Findings suppressed during maintenance |
| **service_renamed_or_rematched** | Node updates identity (old name → new descriptor match) | Continuity preserved: history follows the service, not the container name | Info: "Container now matched to descriptor: Sonarr (was previously unknown)" | Edges may be added/changed based on new descriptor | No incident |

### 14.3 Hard Rules

- **Kaval never auto-deletes services, data, containers, or any system resource.** The v1 action boundary is restart-only.
- **History is always preserved.** Even when a service is removed from the active map, its incidents, journal entries, notes, and audit trail remain in the database and are accessible through the memory browser.
- **Intent detection is best-effort.** Kaval distinguishes intentional vs unexpected removal primarily by context: was the user in maintenance mode? Did the user trigger a removal through the Unraid UI? If ambiguous, Kaval asks: "Container X disappeared — was this intentional?"

---

## 15. Alerting and Notification Operational Model

### 15.1 Core Principle

Notifications are **incident-centered, not finding-centered.** A user should never receive 5 separate notifications for 5 findings that all trace to the same root cause. One root cause = one incident = one notification.

### 15.2 Severity Routing

| Severity | Default behavior | Examples |
|----------|-----------------|----------|
| Critical | Immediate push to all configured channels | Service down, array degraded, disk pre-fail |
| High | Immediate with 15-minute dedup window | VPN tunnel drop, restart storm, TLS failure |
| Medium | Hourly digest (batched into one message) | Cert expiring in 7 days, log error pattern, new unknown container |
| Low | Dashboard only (no push notification) | Image update available, minor resource increase |
| Info | Dashboard only, grouped by day | Service added, adapter configured, edge confirmed |

### 15.3 Notification Content

Every incident notification should contain enough context to decide whether to act without opening the UI:

- **Root cause summary** (one sentence)
- **Affected services** (list)
- **Confidence level**
- **Key evidence** (2-3 bullet points, not a wall of text)
- **Impact assessment** ("Download pipeline blocked. Playback unaffected.")
- **Recommendation** with risk framing
- **Action buttons** (Approve / View Details / Dismiss)
- **Recurrence note** if this is a repeat incident ("This has happened 4 times. Restart resolved it each time.")

### 15.4 Multiple Simultaneous Issues

When multiple unrelated problems occur simultaneously:

- Each gets its own incident (grouping is dependency-based, not time-based only)
- Each gets its own notification (unless in digest mode)
- The highest-severity incident is pushed first
- A summary notification can follow: "2 active incidents: DelugeVPN tunnel down (High), cert expiring on photos.domain.com (Medium)"
- The dashboard shows all active incidents in priority order

### 15.5 Quiet Hours and Maintenance Interaction

- **Quiet hours:** non-critical notifications are held and delivered as a digest when quiet hours end. Critical notifications always push through.
- **Maintenance mode:** all notifications for the service(s) in maintenance are suppressed. If a critical issue affects a non-maintenance service, it still fires.
- **Stacking:** if the same incident persists through quiet hours, one notification is sent when quiet hours end (not N separate ones).

### 15.6 Kaval Self-Health Notifications

Separate from service health notifications. Kaval notifies about its own problems:

- "Local model endpoint is unreachable — investigation capability degraded"
- "Telegram bot token is invalid — notification delivery failing"
- "Deep inspection adapter for NPM failed — falling back to basic monitoring"
- "Database is approaching configured size limit"

These are opt-in (configurable in settings). Default: enabled for critical self-health issues, disabled for minor ones.

### 15.7 Telegram vs UI Interaction Model

| Scenario | Telegram provides | UI provides |
|----------|-------------------|-------------|
| Simple incident with clear fix | Full context + approve/dismiss buttons. User may never need the UI. | Full investigation detail, evidence chain, dependency graph highlighting |
| Complex multi-service incident | Summary + "View in Kaval" link. Telegram is the alert; UI is the investigation workspace. | Full evidence, graph, timeline, research steps |
| Credential request (UAC) | "I need the Radarr API key" + enter/skip/vault buttons | Same flow, plus credential management and vault UI |
| Memory interaction | `/note`, `/journal`, `/recurrence` commands for quick access | Full memory browser, note editor, journal search |
| Configuration changes | Not in Telegram — admin operations happen in UI | Settings, descriptor editor, adapter configuration |

---

## 16. Auto-Generated Descriptor Lifecycle

### 12.1 Trigger

When Kaval discovers a container that doesn't match any shipped descriptor:

1. Container is monitored generically (Level 0)
2. If a local model is available, Kaval can attempt to generate a descriptor from: Docker image metadata, container labels, exposed ports, volume mounts, known image registry data
3. Generation is optional and user-configurable (enabled/disabled in settings)

### 12.2 Quarantine

Auto-generated descriptors follow the existing 8 quarantine rules from the PRD, plus:

- Stored in a separate `auto_generated/` directory
- Tagged with `verified: false`, `source: auto_generated`, `generated_at: timestamp`
- Visible in the UI with a distinct "needs review" badge
- Never used for: action recommendations, incident grouping edge inputs, or investigation recommendations that reference auto-generated-only evidence
- Only used for: basic endpoint probing, log error scanning, and UI display

### 12.3 Review Workflow

In the descriptor editor UI:

- "Auto-generated descriptors" queue shows pending reviews
- For each: show the generated descriptor alongside the container's actual metadata
- User can: promote (move to user descriptors, mark verified), edit then promote, dismiss (mark as not useful), or defer review
- Promoted descriptors gain full monitoring capability
- Dismissed containers stay at generic Level 0 monitoring

### 12.4 Community Contribution Path

When a user promotes an auto-generated descriptor:
- Kaval can offer to export it in a contributor-friendly format
- "This descriptor might help other users with the same service. Would you like to share it?"
- Export produces a clean YAML file suitable for a GitHub PR to the shipped descriptors

---

## 17. External API Integrations

### 17.1 Design Principles

All external API integrations follow the same rules:

- Read-only: no mutations, no config changes, no state modifications
- Credential-gated: access requires explicit user opt-in and credential provision
- Investigation-time: called during evidence gathering, not continuously polled (unless configured for periodic deep inspection)
- Structured output: return typed facts, not raw API responses
- Two-level redaction: facts are redacted appropriately before LLM prompt inclusion
- Graceful degradation: if the integration fails, investigation continues without it

### 17.2 Cloudflare Integration

**Credential:** Cloudflare API token (scoped to Zone:Read, DNS:Read)  
**Surfaces:**

| Surface | What it provides | Investigation use |
|---------|-----------------|------------------|
| DNS records | A, AAAA, CNAME records for zone | Verify DNS points to correct targets during DNS investigation |
| Proxy mode | Per-record proxy status (orange cloud vs gray) | Understand whether traffic goes through Cloudflare proxy |
| SSL/TLS mode | Full, Flexible, Strict, Origin Server | Critical for TLS investigation — determines what certs are needed |
| Origin certificates | Cloudflare-issued origin certs | Check validity, expiry, cipher compatibility |
| Tunnel config | Tunnel routes, ingress rules | Map tunnel → origin service relationships |
| Firewall rules | Active WAF/firewall rules | Identify blocked traffic patterns |

**Dependency graph enrichment:** Cloudflare integration can discover: domain → tunnel → origin service mappings, which creates high-confidence `runtime_observed` edges between Cloudflare, cloudflared, and upstream services.

### 17.3 Authentik Integration

**Credential:** Authentik API token  
**Surfaces:**

| Surface | What it provides | Investigation use |
|---------|-----------------|------------------|
| Applications | List of configured apps with launch URLs | Map which services are SSO-protected |
| Providers | OIDC/SAML/LDAP providers with health | Identify SSO chain failures |
| Outposts | Proxy outpost health and configuration | Identify authentication proxy issues |
| System health | Authentik's own health check | Distinguish Authentik failure from downstream SSO failures |

**Dependency graph enrichment:** Authentik integration discovers which services are SSO-protected, creating dependency edges from those services to Authentik.

### 17.4 Future Integration Pattern

The same pattern applies to any future external integration:

1. Declare surfaces in the service descriptor
2. Implement a typed adapter following the common interface
3. Register the adapter in the discovery/inspection system
4. Facts flow into evidence gathering during investigation
5. Dependency edges are enriched with higher confidence

---

## 18. Descriptor Expansion

### 18.1 Target: 50+ Shipped Descriptors

Current: 15 shipped descriptors. Target: 50+ covering the most common homelab Docker images.

**Additional categories to cover:**

| Category | Services | Priority |
|----------|----------|----------|
| Media (additional) | Emby, Tautulli, Kometa, Bazarr, Lidarr, Readarr, Overseerr, Ombi | High |
| Downloads (additional) | Transmission, SABnzbd, Gluetun, NZBGet | High |
| Networking (additional) | Traefik, Caddy, AdGuard Home, Tailscale, WireGuard | High |
| Identity (additional) | Authelia, Keycloak, LLDAP | Medium |
| Cloud (additional) | Vaultwarden, Paperless-ngx, Bookstack, Gitea, Seafile, Syncthing | Medium |
| Monitoring (additional) | Grafana, Prometheus, InfluxDB, Netdata, Telegraf, cAdvisor | Medium |
| Databases (additional) | PostgreSQL, Redis, MongoDB, Valkey | Medium |
| System (additional) | Portainer, Watchtower, Duplicati, Kopia, Dozzle, FileBrowser | Medium |
| Gaming | Minecraft Server, Valheim, Palworld | Lower |
| Development | Gitea, Forgejo, Code Server, n8n, Node-RED | Lower |
| Home automation | Zigbee2MQTT, MQTT (Mosquitto), ESPHome, Frigate | Medium |

### 18.2 Descriptor Quality Standards

Every shipped descriptor must include:

- At least one image pattern match
- At least one health endpoint
- At least 3 log signal patterns (errors + warnings)
- Dependency hints where applicable
- At least one common failure mode
- Investigation context paragraph
- Contract test coverage (validates against schema, loads without error)

Descriptors for high-priority services should also include:

- Inspection surface declarations (for deep inspection adapters)
- Credential hints with user-friendly descriptions
- Multiple image pattern matches (linuxserver, hotio, official, etc.)

---

## 19. VMs and Plugins

### 19.1 VM Monitoring (Current State)

Kaval already monitors VMs via the Unraid API: running/stopped/paused state, resource allocation, hosted service reachability via endpoint probes.

### 19.2 VM Insight Gaps

What Kaval doesn't currently do for VMs:

- **Guest-level service discovery:** Kaval knows "Ubuntu Server VM is running" but not "it's running Moodle on Apache with MariaDB inside"
- **Guest health checks:** No visibility into guest OS health (disk space, CPU, memory, process state)
- **Guest log access:** Cannot read logs from services running inside VMs

### 19.3 VM Strategy

For v1, accept that VMs are opaque boxes with external probing only:

- Endpoint probes confirm hosted services are reachable
- User notes fill in the operational knowledge ("This VM runs Moodle, check LVM partition first if disk issues")
- The dependency graph shows VM → hosted services as user-confirmed edges

For future versions, consider:
- Guest agent (lightweight agent installed inside VMs that reports to Kaval)
- SSH-based inspection (with explicit user opt-in and credential management)
- VM-specific descriptors that describe what's running inside

### 19.4 VM Graph Representation

In the dependency graph, VMs appear as nodes like Docker services but with distinct visual treatment:

- **VM node type:** visually distinct from container nodes (different shape or icon)
- **Hosted services as child nodes:** when the user confirms "this VM runs Moodle," Moodle appears as a child node of the VM, with a user-confirmed edge
- **Insight level:** VMs default to Level 0 (Discovered) since no descriptor matching applies. With user notes and confirmed hosted services, they reach Level 5 (Operator-enriched).
- **External probing:** endpoint probe results are shown on the VM node (reachable or unreachable for each known hosted service)
- **The guided setup should prompt:** "I found 3 VMs. Do any of these host services you'd like Kaval to monitor?" with fields to add hosted service names and their accessible endpoints

### 19.5 Plugin Monitoring (Current State)

Kaval monitors Unraid plugins via the Unraid API: installed, enabled, version, update availability.

### 19.6 Plugin Classification

Plugins are NOT first-class service nodes in the dependency graph. They are system facets — properties of the Unraid host that can affect services.

- Plugins appear in the **system profile** and the **system health section** of the UI, not as nodes in the service map
- Plugin state changes (installed, updated, removed) appear in the **change timeline**
- Plugin-to-service impact is captured through **dependency annotations**, not graph edges: "GPU Stats plugin affects Plex transcoding" is a note on the Plex service, not an edge from a "GPU Stats" node to a "Plex" node
- This avoids cluttering the service map with non-service entities

**Exception:** if a plugin runs its own web service (e.g., some monitoring plugins), it MAY appear as a service node if it has a reachable endpoint and a descriptor match.

### 19.7 Plugin Strategy

For v1:
- Plugin health is part of the system profile
- Plugin updates are tracked in the change timeline
- Critical plugin state changes generate findings:
  - **GPU Stats plugin failed/removed** → finding on dependent services (Plex): "GPU transcoding may be affected"
  - **CA plugin failed** → system-level finding: "Community Apps plugin is not functional"
  - **Unraid Connect offline** → system-level finding
- Plugin impact on services is captured in descriptors (`plugin_dependencies` field) and user notes
- The system health summary shows plugin status alongside array, disk, and cache health

---

## 20. Homepage / Homarr Widget API

### 20.1 Endpoint

`GET /api/v1/widget` — returns a compact JSON summary for dashboard widgets.

### 20.2 Response

```json
{
  "status": "healthy",           // or "degraded" or "critical"
  "services_total": 25,
  "services_healthy": 23,
  "services_degraded": 1,
  "services_down": 1,
  "active_incidents": 1,
  "active_findings": 3,
  "last_investigation": "2 hours ago",
  "effectiveness_score": 78,     // percentage of services at max insight level
  "adapters_healthy": 4,
  "adapters_degraded": 1,
  "pending_approvals": 0,
  "url": "http://kaval.local:9800"
}
```

### 20.3 Configuration

- Enable/disable in settings
- Optional API key auth
- Configurable refresh interval recommendation (returned in response headers)

---

## 21. Audit Trail UI

### 21.1 Purpose

Every action Kaval takes should be visible and searchable: checks run, findings created, incidents grouped, investigations triggered, approvals requested, actions executed, credentials used, adapters invoked.

### 21.2 Audit Trail View

- Chronological event stream with filters: event type, service, severity, date range
- Each event shows: timestamp, type, target, trigger, result, model used (if applicable)
- Link from audit event to related finding/incident/investigation
- Export capability (CSV/JSON) for external analysis
- Retention policy: configurable (default: 90 days of detailed events, 1 year of summary events)

---

## 22. Model Usage and Cost Dashboard

### 22.1 Purpose

Users need visibility into how much AI they're using and what it costs.

### 22.2 Dashboard Content

- **Today:** local model calls, cloud model calls, estimated cost
- **This week / this month:** same with trends
- **Per-incident breakdown:** which investigations used cloud, how many tokens, estimated cost
- **Escalation analysis:** what triggered cloud escalation (finding count, low confidence, user request)
- **Budget status:** current spend vs configured daily/monthly limits
- **Model comparison:** if both local and cloud are configured, show quality comparison (user-confirmed vs unconfirmed root causes per model)

---

## 23. Distribution and Packaging

### 23.1 Unraid Community Apps Template

One CA template that installs one Docker container with:
- Port mapping (9800 for UI)
- Volume mapping (/data for persistent state)
- Docker socket mapping (for Executor process)
- Environment variables for: Unraid API key, Telegram bot token (optional), notification channel
- Template description explaining the three operating profiles
- Icon and screenshots

### 23.2 Install and Upgrade Flow

**First install:**
- Container starts → guided setup flow in web UI
- No CLI required
- Minimal env vars needed: Unraid API key only

**Upgrade:**
- Docker image pull + restart
- Database migration runs automatically on startup
- Breaking changes (if any) documented in release notes
- Settings/credentials preserved across upgrades

**Backup and restore:**
- `GET /api/v1/admin/backup` → downloads a ZIP of: database, settings, user descriptors, user notes, operational memory (with sensitivity warning)
- `POST /api/v1/admin/restore` → uploads and restores from backup
- These are manual operations, not automatic — the user decides when to backup

### 23.3 Support Matrix

- Unraid 7.2+
- Docker 24+
- Recommended: Ollama with 8B+ model for investigation capability
- Optional: Cloud model API key for complex investigations
- Browser: modern Chrome, Firefox, Safari, Edge

---

## 24. Documentation Set

### 24.1 User Documentation

| Document | Content | Audience |
|----------|---------|----------|
| **Install Guide** | CA template install, first-run setup, notification configuration | New users |
| **Getting Started** | First-hour walkthrough: understanding the service map, improving insight levels, configuring deep inspection | New users |
| **Operator Guide** | Detailed coverage of all UI features, settings, credential management, maintenance mode, noise control | Active users |
| **Investigation Guide** | How Kaval investigates, what evidence/inference/recommendation means, how to approve actions, how to provide feedback | Active users |
| **Troubleshooting** | Common issues: "Why is Kaval not detecting my service?" "Why are investigations generic?" "How do I reduce false positives?" | All users |
| **FAQ** | Model costs, security model, what Kaval can/cannot do, how data is stored, privacy | All users |

### 24.2 Contributor Documentation

| Document | Content | Audience |
|----------|---------|----------|
| **Descriptor Authoring Guide** | How to write a service descriptor, field reference, testing, submitting PRs | Descriptor contributors |
| **Adapter Development Guide** | How to write a deep inspection adapter, interface contract, testing, version compatibility | Code contributors |
| **Webhook Normalizer Guide** | How to add a new webhook source, normalizer interface, testing | Code contributors |
| **Architecture Guide** | System architecture, data flow, security model, investigation workflow | Code contributors |
| **Development Setup** | Local dev environment, running tests, CI pipeline, coding standards | Code contributors |

### 24.3 In-Product Documentation

- Tooltips on complex UI elements
- "Learn more" links to relevant docs
- Contextual help in the guided setup flow
- Error messages that explain what happened and what to do about it

---

## 25. Security Audit Scope

### 25.1 Areas to Audit

| Area | What to verify |
|------|---------------|
| **LLM confinement** | LLM has no action tools, proposals are data only, execution path is deterministic code |
| **Approval token integrity** | HMAC validation, single-use, time-limited, incident-bound, replay protection |
| **Credential handling** | Secrets never in logs/prompts/UI, vault encryption, volatile mode works, two-level redaction |
| **Executor isolation** | Executor process only accepts socket requests, validates tokens, respects allowlist |
| **Docker socket access** | Only executor process uses docker.sock, core process doesn't bypass |
| **Webhook auth** | Per-source API keys, no unauthenticated webhook acceptance |
| **Admin API auth** | Settings/config/backup endpoints require authentication |
| **Adapter safety** | All adapters are read-only, no state mutations via management surface inspection |
| **Input validation** | User notes, descriptor edits, config changes — all validated and sanitized |
| **Dependency safety** | Third-party Python packages audited, no known CVEs in production dependencies |

### 25.2 Security Test Coverage

- `tests/security/` directory with explicit tests for each area above
- Secret pattern detection: test that known secret formats are caught by redaction
- Token validation: test that expired/reused/malformed tokens are rejected
- Allowlist enforcement: test that non-allowlisted actions are rejected
- Prompt injection: test that malicious content in logs/notes doesn't affect investigation behavior beyond the investigation itself

---

## 26. Performance Targets

### 26.1 Responsiveness

| Operation | Target |
|-----------|--------|
| UI initial load | < 3 seconds |
| Service map render (25 services) | < 1 second |
| Service map render (100 services) | < 3 seconds |
| API response (service list) | < 200ms |
| API response (service detail) | < 500ms |
| Investigation (local model) | < 30 seconds |
| Investigation (cloud model) | < 60 seconds |
| Webhook ingestion to finding creation | < 2 seconds |
| Check cycle (all checks, 25 services) | < 30 seconds |

### 26.2 Resource Usage

| Resource | Target |
|----------|--------|
| Idle memory (Core + Executor) | < 256 MB |
| Active memory (during investigation) | < 512 MB |
| Database size (1 year of data, 25 services) | < 500 MB |
| CPU idle | < 2% of a modern core |
| CPU during check cycle | < 10% of a modern core |

### 26.3 Scale

| Dimension | Supported |
|-----------|-----------|
| Services (containers + VMs) | Up to 100 |
| Shipped descriptors | 50+ |
| Active findings | Up to 500 |
| Incident history | Up to 10,000 |
| Journal entries | Up to 5,000 |
| User notes | Up to 1,000 |
| Concurrent webhook sources | Up to 10 |

---

## 27. Release Quality Checklist

### 27.1 Hard Release Gates (must pass before CA template distribution)

These are non-negotiable. The release is blocked until all pass:

- [ ] All shipped descriptors pass contract tests
- [ ] Security audit items all verified with passing tests (Section 25)
- [ ] Secrets audit: no secrets in logs, prompts, UI, git-tracked files, exported data
- [ ] Install flow tested: CA template install → API key → service map in < 2 minutes
- [ ] Upgrade flow tested: image pull → restart → data preserved → no regressions
- [ ] Guided setup flow complete and functional
- [ ] Core documentation written: install guide, getting started, operator guide
- [ ] Notification tested on at least 2 channels (Telegram + one other)
- [ ] Adapter degradation tested: break each priority adapter → verify graceful fallback
- [ ] Action boundary verified: LLM cannot trigger actions, approval token validation works, Executor allowlist enforced

### 27.2 Quality Targets (should pass, investigated if not)

These represent the expected quality level. Failures are investigated and either fixed or documented with justification:

- [ ] All priority adapters have fixture-based tests across at least 2 service versions
- [ ] Performance targets met on representative hardware (Intel i3-12100T, 32GB RAM, NVMe)
- [ ] Contributor guides tested: follow the guide → produce a working descriptor/adapter/normalizer
- [ ] Screenshot/demo content produced
- [ ] Browser compatibility verified: Chrome and Firefox (primary), Safari (best effort)
- [ ] False positive assessment: run for 48 hours on a real server, evaluate noise level
- [ ] Notification tested across 3+ channels (Telegram, ntfy, Discord)

### 27.3 Stretch Goals (aspirational, not release-blocking)

These improve the product but are not required for initial distribution:

- [ ] False positive rate below 5/day sustained over 1 week on a real server
- [ ] Full mobile responsiveness (service map and all views usable on phone)
- [ ] All 50+ descriptor targets shipped (30+ is the hard target)
- [ ] All contributor documentation tested with external contributors
- [ ] Performance validated at 100-service scale (25-service is the hard target)

---

## Appendix A: Summary of Gaps by Category

| Category | What exists (Phase 2B) | What's missing |
|----------|----------------------|----------------|
| **Service understanding** | Docker inference, descriptors, log patterns | Deep inspection via service APIs, insight level model, adapter framework |
| **User trust** | Investigation with evidence/inference/recommendation | Insight transparency, false positive controls, investigation quality feedback, effectiveness score |
| **Self-awareness** | — | Kaval capability health dashboard, adapter health, self-diagnostics across all layers |
| **UX** | Service map, investigation detail, approval queue | Guided setup, descriptor editor, settings UI, interactive graph editing, maintenance mode |
| **Integration** | Tier 2 research (GitHub, Docker Hub) | Webhook ingestion, Cloudflare, Authentik, Prometheus metrics, Homepage widget |
| **Memory UX** | Backend: journal, notes, redaction, recurrence | UI: memory browser with provenance, note management, recurrence reports, facts tab, Telegram memory commands |
| **Admin** | YAML config file | Settings UI, credential management UI, audit trail UI, cost dashboard, single-admin access model |
| **Monitoring model** | Scheduler with per-check intervals | Documented cadence defaults, incident-triggered acceleration, topology refresh model, adapter cadence |
| **Service lifecycle** | Change detection for image updates and restarts | Explicit add/remove/rename lifecycle events with map/history/notification behavior |
| **Alerting UX** | Incident-grouped notifications via apprise | Severity routing, digest behavior, quiet hours, multi-issue handling, self-health alerts, Telegram vs UI model |
| **Action boundary** | Restart-only executor with HMAC tokens | Explicit reassertion that Phase 3/4 are read-only; no action scope expansion |
| **Descriptors** | 15 shipped, quarantine rules defined | 50+ shipped, auto-generation workflow, descriptor editor, community contribution path |
| **Distribution** | Docker image builds | CA template, install guide, documentation set, contributor guides |
| **Quality** | CI tests, security tests | Security audit, performance profiling, tiered release checklist |

## Appendix B: Likely ADR Candidates

These are architectural decisions that should be formally recorded if/when they're made:

| ADR | Decision |
|-----|----------|
| ADR-015 | Service Insight Level model and per-service capability representation |
| ADR-016 | Deep inspection adapter interface contract and version compatibility model |
| ADR-017 | Canonical webhook event schema and normalized ingestion pipeline |
| ADR-018 | Settings/configuration persistence model (YAML vs DB vs hybrid, hot-reload behavior) |
| ADR-019 | Auto-generated descriptor quarantine enforcement and promotion workflow |
| ADR-020 | Kaval capability health model and self-diagnostics approach |
| ADR-021 | Service lifecycle event model and removal/archival behavior |

## Appendix C: Likely CR Candidates

| CR | Scope |
|----|-------|
| CR-0003 | PRD sync to Phase 2B + ADR-014 reality (housekeeping) |
| CR-0004 | Service Insight Model + deep inspection + adapter health requirements |
| CR-0005 | Webhook ingestion + alerting operational model requirements |
| CR-0006 | Admin UX, guided setup, noise control, and service lifecycle requirements |
| CR-0007 | Distribution, documentation, and release-readiness requirements |
| CR-0008 | Descriptor expansion targets, auto-generation lifecycle, and monitoring cadence model |
