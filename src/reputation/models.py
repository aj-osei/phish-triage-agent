"""Normalized result models shared by reputation providers."""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class ReputationResult:
    """One provider result formatted for safe report rendering."""

    category: str
    provider: str
    status: str
    details: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        """Return a plain dictionary used by the report renderer."""
        return {
            "category": self.category,
            "provider": self.provider,
            "status": self.status,
            "details": self.details,
        }
