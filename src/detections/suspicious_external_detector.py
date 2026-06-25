import ipaddress
from typing import List
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

class SuspiciousExternalDetector(BaseDetector):
    def get_name(self) -> str:
        return "Suspicious External Communication Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        for r in records:
            if not r.source_ip or not r.destination_ip:
                continue
                
            # If source is private and destination is NOT private, it's outbound external
            if is_private_ip(r.source_ip) and not is_private_ip(r.destination_ip):
                
                # Basic checks for suspicious nature: high ports, odd protocols
                # In a real engine, we'd use threat intel feeds. 
                # Here we will flag high data transfer on non-standard ports to external IPs
                port = r.destination_port
                bytes_out = r.bytes_sent or 0
                
                is_suspicious = False
                reason = ""
                severity = Severity.LOW
                
                if port and port not in [80, 443, 53, 123, 22]:
                    if bytes_out > 1000000: # 1MB
                        is_suspicious = True
                        reason = f"High data transfer ({bytes_out} bytes) on non-standard external port {port}"
                        severity = Severity.HIGH
                        
                # Also check connection state indicating weirdness
                if r.state in ['RSTR', 'SHR']:
                    is_suspicious = True
                    reason = f"Suspicious connection state {r.state} to external IP"
                    severity = Severity.MEDIUM
                    
                if is_suspicious:
                    findings.append(Finding(
                        title=f"Suspicious External Comm to {r.destination_ip}",
                        description=reason,
                        severity=severity,
                        source_ip=r.source_ip,
                        destination_ip=r.destination_ip,
                        port=port,
                        protocol=r.protocol,
                        detection_type="Suspicious External",
                        timestamp=r.timestamp,
                        evidence={"bytes_sent": bytes_out, "state": r.state},
                        raw_data=r.raw_data
                    ))

        return findings
