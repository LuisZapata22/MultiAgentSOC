import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector

class BeaconingDetector(BaseDetector):
    def get_name(self) -> str:
        return "Beaconing Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        # Group timestamps by (src, dst, port)
        connection_times = defaultdict(list)
        latest_record_by_pair = {}
        
        for r in records:
            if not r.source_ip or not r.destination_ip:
                continue
            
            pair = (r.source_ip, r.destination_ip, r.destination_port)
            connection_times[pair].append(r.timestamp.timestamp())
            latest_record_by_pair[pair] = r

        for pair, times in connection_times.items():
            if len(times) < 5:
                continue
                
            times.sort()
            # Calculate intervals
            intervals = [times[i] - times[i-1] for i in range(1, len(times))]
            
            mean_interval = np.mean(intervals)
            if mean_interval == 0:
                continue
                
            std_dev = np.std(intervals)
            cv = std_dev / mean_interval
            
            # Low CV means highly regular
            if cv < 0.2:
                src, dst, port = pair
                count = len(times)
                
                severity = Severity.LOW
                if count > 50:
                    severity = Severity.HIGH
                elif count > 20:
                    severity = Severity.MEDIUM
                    
                findings.append(Finding(
                    title=f"Beaconing Detected from {src} to {dst}",
                    description=f"Highly regular communication pattern detected ({count} connections, mean interval {mean_interval:.1f}s, CV {cv:.3f}).",
                    severity=severity,
                    source_ip=src,
                    destination_ip=dst,
                    port=port,
                    detection_type="Beaconing",
                    timestamp=latest_record_by_pair[pair].timestamp,
                    evidence={"connection_count": count, "mean_interval_sec": mean_interval, "cv": cv},
                    raw_data=latest_record_by_pair[pair].raw_data
                ))

        return findings
