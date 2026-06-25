from typing import List
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector

class UnusualPortDetector(BaseDetector):
    def get_name(self) -> str:
        return "Unusual Port Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        # Mappings of standard ports to services
        standard_ports = {
            22: 'ssh',
            80: 'http',
            443: 'ssl',
            3389: 'rdp',
            53: 'dns'
        }

        for r in records:
            if not r.destination_port or not r.service:
                continue
            
            port = r.destination_port
            service = r.service.lower()
            
            if service in ['-', 'other', '']:
                continue
                
            # If service is known but port is unusual
            is_unusual = False
            for std_port, std_srv in standard_ports.items():
                if service == std_srv and port != std_port:
                    is_unusual = True
                    break
            
            if is_unusual:
                findings.append(Finding(
                    title=f"Unusual Port for Service {service}",
                    description=f"Service '{service}' detected on non-standard port {port}.",
                    severity=Severity.LOW,
                    source_ip=r.source_ip or "unknown",
                    destination_ip=r.destination_ip,
                    port=port,
                    protocol=r.protocol,
                    detection_type="Unusual Ports",
                    timestamp=r.timestamp,
                    evidence={"service": service, "port": port},
                    raw_data=r.raw_data
                ))

        return findings
