"""Compatibility shim: expose CorrelationEngine at package root.
Some modules import `correlation_engine` directly; forward to `modules.correlation_engine`.
"""
from modules.correlation_engine import CorrelationEngine  # noqa: F401
