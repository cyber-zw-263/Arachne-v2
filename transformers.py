"""
Minimal shim for `transformers` to satisfy test imports/patching in CI/dev.
This file intentionally provides a no-op `pipeline` symbol so tests can patch it.
"""
from typing import Any

def pipeline(*args: Any, **kwargs: Any):
    """Return a callable-like object placeholder for tests to patch."""
    def _inner(*a, **k):
        return []
    return _inner
