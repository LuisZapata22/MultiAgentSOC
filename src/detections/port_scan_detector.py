from typing import List, Dict, Set
from collections import defaultdict
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector

class PortScanDetector(BaseDetector):
    def get_name(self) -> str:
        return "Port Scan Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        # Track for vertical scan: source -> target -> set of ports
        vertical_scans = defaultdict(lambda: defaultdict(set))
        # Track for horizontal scan: source -> port -> set of targets
        horizontal_scans = defaultdict(lambda: defaultdict(set))
        # Keep one record per source for timestamp/evidence
        latest_record_by_src = {}

        for r in records:
            if not r.source_ip or not r.destination_ip or not r.destination_port:
                continue
            
            src = r.source_ip
            dst = r.destination_ip
            port = r.destination_port
            
            vertical_scans[src][dst].add(port)
            horizontal_scans[src][port].add(dst)
            latest_record_by_src[src] = r

        # Evaluate Vertical Scans
        for src, targets in vertical_scans.items():
            for dst, ports in targets.items():
                if len(ports) > 15:
                    count = len(ports)
                    severity = Severity.MEDIUM
                    if count > 100:
                        severity = Severity.CRITICAL
                    elif count > 30:
                        severity = Severity.HIGH
                        
                    findings.append(Finding(
                        title=f"Vertical Port Scan Detected from {src} to {dst}",
                        description=f"Source {src} scanned {count} unique ports on {dst}.",
                        severity=severity,
                        source_ip=src,
                        destination_ip=dst,
                        detection_type="Port Scan (Vertical)",
                        timestamp=latest_record_by_src[src].timestamp,
                        evidence={"ports_scanned": count},
                        raw_data=latest_record_by_src[src].raw_data
                    ))

        # Evaluate Horizontal Scans
        for src, ports in horizontal_scans.items():
            for port, targets in ports.items():
                if len(targets) > 10:
                    count = len(targets)
                    severity = Severity.MEDIUM
                    if count > 100:
                        severity = Severity.CRITICAL
                    elif count > 30:
                        severity = Severity.HIGH
                        
                    findings.append(Finding(
                        title=f"Horizontal Port Scan Detected from {src} on port {port}",
                        description=f"Source {src} scanned {count} unique hosts on port {port}.",
                        severity=severity,
                        source_ip=src,
                        port=port,
                        detection_type="Port Scan (Horizontal)",
                        timestamp=latest_record_by_src[src].timestamp,
                        evidence={"hosts_scanned": count, "target_port": port},
                        raw_data=latest_record_by_src[src].raw_data
                    ))

        return findings
