from abc import ABC, abstractmethod
from typing import List
from src.models.schemas import TelemetryRecord, Finding

class BaseDetector(ABC):
    @abstractmethod
    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        """Analyze records and return findings."""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return the name of the detector."""
        pass
