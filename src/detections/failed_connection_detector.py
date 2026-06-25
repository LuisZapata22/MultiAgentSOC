from typing import List
from collections import defaultdict
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector

class FailedConnectionDetector(BaseDetector):
    def get_name(self) -> str:
        return "Failed Connection Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        failed_states = {'REJ', 'S0', 'RSTO', 'RSTOS0'}
        failures_by_src_dst = defaultdict(int)
        latest_record = {}
        
        for r in records:
            if not r.source_ip or not r.destination_ip:
                continue
                
            if r.state in failed_states:
                pair = (r.source_ip, r.destination_ip)
                failures_by_src_dst[pair] += 1
                latest_record[pair] = r

        for (src, dst), count in failures_by_src_dst.items():
            if count > 20:
                severity = Severity.MEDIUM
                if count > 100: severity = Severity.HIGH
                
                findings.append(Finding(
                    title=f"High Failure Rate to {dst}",
                    description=f"Source {src} experienced {count} failed connections to {dst}.",
                    severity=severity,
                    source_ip=src,
                    destination_ip=dst,
                    detection_type="Failed Connections",
                    timestamp=latest_record[(src, dst)].timestamp,
                    evidence={"failed_count": count},
                    raw_data=latest_record[(src, dst)].raw_data
                ))

        return findings
