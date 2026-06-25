from typing import List, Dict, Set
from collections import defaultdict
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector
from src.detections.suspicious_external_detector import is_private_ip

class LateralMovementDetector(BaseDetector):
    def get_name(self) -> str:
        return "Lateral Movement Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        # admin_ports: RDP, SMB, SSH, WinRM
        admin_ports = {3389: "RDP", 445: "SMB", 22: "SSH", 5985: "WinRM", 5986: "WinRM"}
        
        targets_by_src_port = defaultdict(lambda: defaultdict(set))
        latest_record = {}

        for r in records:
            if not r.source_ip or not r.destination_ip or not r.destination_port:
                continue
                
            port = r.destination_port
            if port in admin_ports:
                if is_private_ip(r.source_ip) and is_private_ip(r.destination_ip):
                    src = r.source_ip
                    dst = r.destination_ip
                    targets_by_src_port[src][port].add(dst)
                    latest_record[(src, port)] = r

        for src, ports in targets_by_src_port.items():
            for port, targets in ports.items():
                if len(targets) > 5:
                    count = len(targets)
                    protocol_name = admin_ports[port]
                    
                    severity = Severity.MEDIUM
                    if count > 20: severity = Severity.HIGH
                    if count > 50: severity = Severity.CRITICAL
                    
                    findings.append(Finding(
                        title=f"Lateral Movement ({protocol_name}) from {src}",
                        description=f"Source {src} connected to {count} internal hosts via {protocol_name} (Port {port}).",
                        severity=severity,
                        source_ip=src,
                        port=port,
                        protocol=protocol_name,
                        detection_type=f"Lateral Movement ({protocol_name})",
                        timestamp=latest_record[(src, port)].timestamp,
                        evidence={"targets_count": count, "admin_port": port},
                        raw_data=latest_record[(src, port)].raw_data
                    ))

        return findings
