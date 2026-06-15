"""Adapters — translate framework events into Core calls.

One module per framework. Each adapter MUST:
  • depend on clawkeeper_core, not vice versa
  • expose `install(judge, agent_or_runtime, **opts)` as its public API
  • be importable without the framework actually installed (lazy imports)
"""
