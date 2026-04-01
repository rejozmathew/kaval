"""Runtime entrypoint for the long-running Core API/UI process."""

from __future__ import annotations

import os

import uvicorn


def main() -> int:
    """Run the FastAPI-based Core process on the configured host and port."""
    host = os.environ.get("KAVAL_CORE_HOST", "0.0.0.0")
    port = int(os.environ.get("KAVAL_CORE_PORT", "9800"))
    log_level = os.environ.get("KAVAL_CORE_LOG_LEVEL", "info")
    uvicorn.run("kaval.api.app:app", host=host, port=port, log_level=log_level)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
