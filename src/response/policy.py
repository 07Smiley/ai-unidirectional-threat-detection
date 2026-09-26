"""Configurable, user-controlled threat response policy."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatResponsePolicy:
    """Decide when the UI should offer a response action.

    A threshold only creates an offer; it never performs a network action.
    """

    threshold: float = 0.92
    ask_before_switch: bool = True
    ask_before_block: bool = True

    def requires_user_confirmation(self, confidence: float) -> bool:
        return float(confidence) >= self.threshold
