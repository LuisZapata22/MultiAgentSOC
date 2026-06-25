import ipaddress
from typing import List
from collections import defaultdict
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector
from src.detections.suspicious_external_detector import is_private_ip

class DataExfiltrationDetector(BaseDetector):
    def get_name(self) -> str:
        return "Data Exfiltration Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        # Track bytes out per internal source to external destination
        bytes_out_by_src_dst = defaultdict(int)
        bytes_in_by_src_dst = defaultdict(int)
        latest_record = {}

        for r in records:
            if not r.source_ip or not r.destination_ip:
                continue
                
            if is_private_ip(r.source_ip) and not is_private_ip(r.destination_ip):
                pair = (r.source_ip, r.destination_ip)
                bytes_out_by_src_dst[pair] += (r.bytes_sent or 0)
                bytes_in_by_src_dst[pair] += (r.bytes_received or 0)
                latest_record[pair] = r

        for pair, bytes_out in bytes_out_by_src_dst.items():
            src, dst = pair
            bytes_in = bytes_in_by_src_dst[pair]
            
            is_exfil = False
            reason = ""
            severity = Severity.MEDIUM
            
            # > 10MB to single external dest
            if bytes_out > 10 * 1024 * 1024:
                is_exfil = True
                reason = f"Large outbound data transfer: {bytes_out / (1024*1024):.2f} MB"
                severity = Severity.HIGH
                if bytes_out > 100 * 1024 * 1024:
                    severity = Severity.CRITICAL
            
            # Or asymmetry ratio > 3:1 and at least 1MB out
            elif bytes_out > 1024 * 1024 and bytes_in > 0:
                ratio = bytes_out / bytes_in
                if ratio > 3.0:
                    is_exfil = True
                    reason = f"High upload/download asymmetry (Ratio {ratio:.1f}:1, {bytes_out} bytes out)"
                    
            if is_exfil:
                findings.append(Finding(
                    title=f"Potential Data Exfiltration to {dst}",
                    description=reason,
                    severity=severity,
                    source_ip=src,
                    destination_ip=dst,
                    detection_type="Data Exfiltration",
                    timestamp=latest_record[pair].timestamp,
                    evidence={"bytes_out": bytes_out, "bytes_in": bytes_in},
                    raw_data=latest_record[pair].raw_data
                ))

        return findings
