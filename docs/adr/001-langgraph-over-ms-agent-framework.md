# ADR-001: LangGraph Over Microsoft Agent Framework

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval's core product behavior is a staged investigation workflow with explicit state transitions, checkpointable execution, human approval pauses, and structured outputs. The orchestration layer must fit a Python-first backend, remain model-agnostic, and support durable graph-shaped workflows rather than opaque agent loops.

## Decision

Kaval will use LangGraph as the workflow orchestration layer for investigations and related agent flows. Kaval will not adopt the Microsoft Agent Framework as the primary runtime.

## Consequences

- Investigation logic can be modeled as explicit graph state with typed inputs and outputs.
- Human-in-the-loop approval steps and resumable workflows fit the architecture directly.
- The runtime stays aligned with the Python, FastAPI, and Pydantic stack defined in the PRD.
- Kaval owns its tool adapters and domain contracts instead of inheriting a larger external agent platform boundary.
