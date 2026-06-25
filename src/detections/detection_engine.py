from typing import List
from src.models.schemas import TelemetryRecord, Finding
from src.detections.base_detector import BaseDetector
from src.detections.port_scan_detector import PortScanDetector
from src.detections.beaconing_detector import BeaconingDetector
from src.detections.dns_anomaly_detector import DNSAnomalyDetector
from src.detections.suspicious_external_detector import SuspiciousExternalDetector
from src.detections.failed_connection_detector import FailedConnectionDetector
from src.detections.unusual_port_detector import UnusualPortDetector
from src.detections.data_exfiltration_detector import DataExfiltrationDetector
from src.detections.lateral_movement_detector import LateralMovementDetector

class DetectionEngine:
    def __init__(self):
        self.detectors: List[BaseDetector] = [
            PortScanDetector(),
            BeaconingDetector(),
            DNSAnomalyDetector(),
            SuspiciousExternalDetector(),
            FailedConnectionDetector(),
            UnusualPortDetector(),
            DataExfiltrationDetector(),
            LateralMovementDetector()
        ]

    def run(self, records: List[TelemetryRecord]) -> List[Finding]:
        all_findings = []
        for detector in self.detectors:
            findings = detector.detect(records)
            all_findings.extend(findings)
            
        # Deduplication
        dedup_map = {}
        for f in all_findings:
            key = (f.source_ip, f.destination_ip, f.detection_type, f.port)
            if key not in dedup_map:
                dedup_map[key] = f
            else:
                # keep highest severity
                existing = dedup_map[key]
                severity_rank = {"Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
                if severity_rank.get(f.severity.value, 0) > severity_rank.get(existing.severity.value, 0):
                    dedup_map[key] = f

        final_findings = list(dedup_map.values())
        
        # Sort by severity descending, then timestamp descending
        severity_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
        final_findings.sort(key=lambda x: (severity_rank.get(x.severity.value, 0), x.timestamp.timestamp()), reverse=True)
        
        return final_findings
