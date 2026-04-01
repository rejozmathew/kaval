"""Smoke tests for the Phase 0 scaffold."""


def test_core_package_importable() -> None:
    """Ensure the core package is importable from the source layout."""
    import kaval

    assert kaval.__doc__ == "Kaval core package."


def test_executor_package_importable() -> None:
    """Ensure the executor package is importable from the source layout."""
    from kaval import executor

    assert executor.__doc__ == "Internal executor process for approval-gated restart actions."
