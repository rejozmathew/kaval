"""Integration package."""

from kaval.integrations.adapter_diagnostics import (
    AdapterDiagnosticCheck,
    AdapterDiagnosticCheckResult,
    AdapterDiagnosticOutcome,
    AdapterDiagnosticResult,
    AdapterDiagnosticStatus,
    build_adapter_diagnostic_result,
    run_adapter_diagnostic,
)
from kaval.integrations.adapter_fallback import (
    AdapterFactFreshness,
    AdapterFallbackDecision,
    AdapterFallbackState,
    AdapterRuntimeObservedDowngradePolicy,
    AdapterStalenessPolicy,
    apply_adapter_fallback_to_insight_level,
    apply_runtime_observed_fallback,
    evaluate_adapter_fact_freshness,
    evaluate_adapter_fallback,
)
from kaval.integrations.adapter_refresh import (
    AdapterRefreshConfig,
    AdapterRefreshDecision,
    AdapterRefreshPolicy,
    AdapterRefreshRequest,
    AdapterRefreshScheduler,
    AdapterRefreshTrigger,
    default_adapter_refresh_policies,
    resolve_adapter_refresh_decision,
    resolve_adapter_refresh_policy,
)
from kaval.integrations.authentik_adapter import AuthentikAdapter
from kaval.integrations.cloudflare_adapter import CloudflareAdapter
from kaval.integrations.npm_adapter import NginxProxyManagerAdapter
from kaval.integrations.pihole_adapter import PiHoleAdapter
from kaval.integrations.radarr_adapter import RadarrAdapter
from kaval.integrations.service_adapters import (
    AdapterDiscoveredEdge,
    AdapterRegistry,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
    ServiceAdapter,
    execute_service_adapter,
)

__all__ = [
    "AdapterDiagnosticCheck",
    "AdapterDiagnosticCheckResult",
    "AdapterDiagnosticOutcome",
    "AdapterDiagnosticResult",
    "AdapterDiagnosticStatus",
    "AdapterFactFreshness",
    "AdapterFallbackDecision",
    "AdapterFallbackState",
    "AdapterRuntimeObservedDowngradePolicy",
    "AdapterRefreshConfig",
    "AdapterRefreshDecision",
    "AdapterRefreshPolicy",
    "AdapterRefreshRequest",
    "AdapterRefreshScheduler",
    "AdapterRefreshTrigger",
    "AdapterDiscoveredEdge",
    "AdapterRegistry",
    "AdapterResult",
    "AdapterStalenessPolicy",
    "AdapterStatus",
    "AdapterSurfaceBinding",
    "AuthentikAdapter",
    "CloudflareAdapter",
    "NginxProxyManagerAdapter",
    "PiHoleAdapter",
    "RadarrAdapter",
    "ServiceAdapter",
    "apply_adapter_fallback_to_insight_level",
    "apply_runtime_observed_fallback",
    "build_adapter_diagnostic_result",
    "default_adapter_refresh_policies",
    "evaluate_adapter_fact_freshness",
    "evaluate_adapter_fallback",
    "execute_service_adapter",
    "resolve_adapter_refresh_decision",
    "resolve_adapter_refresh_policy",
    "run_adapter_diagnostic",
]
