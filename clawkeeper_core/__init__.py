"""clawkeeper-core — framework-agnostic safety core for LLM agents.

Public surface re-exports the things adapters most often need:

    from clawkeeper_core import Judge, JudgeContext, Decision

See DESIGN.md for the full API.
"""

from clawkeeper_core.judge import Judge
from clawkeeper_core.schemas import (
    Decision,
    JudgeContext,
    Message,
    Policy,
    ToolCall,
)

__version__ = "0.2.0.dev0"

__all__ = [
    "Decision",
    "Judge",
    "JudgeContext",
    "Message",
    "Policy",
    "ToolCall",
    "__version__",
]
