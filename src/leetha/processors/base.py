"""Base class for all packet processors."""
from __future__ import annotations

from abc import ABC, abstractmethod
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


class Processor(ABC):
    """Abstract base for protocol processors.

    Subclasses implement analyze() to extract Evidence from a CapturedPacket.
    Use @register_processor to declare which protocols a processor handles.
    """

    @abstractmethod
    def analyze(self, packet: CapturedPacket) -> list[Evidence]:
        """Analyze a packet and return evidence found."""
        ...
