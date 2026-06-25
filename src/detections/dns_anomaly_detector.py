import math
from typing import List, Dict, Set
from collections import defaultdict
from src.models.schemas import TelemetryRecord, Finding, Severity
from src.detections.base_detector import BaseDetector

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

class DNSAnomalyDetector(BaseDetector):
    def get_name(self) -> str:
        return "DNS Anomaly Detector"

    def detect(self, records: List[TelemetryRecord]) -> List[Finding]:
        findings: List[Finding] = []
        
        queries_by_src = defaultdict(set)
        latest_record_by_src = {}

        for r in records:
            if not r.dns_query or not r.source_ip:
                continue
                
            src = r.source_ip
            query = r.dns_query
            queries_by_src[src].add(query)
            latest_record_by_src[src] = r
            
            # Check for specific anomalies per query
            length = len(query)
            entropy = shannon_entropy(query)
            subdomain_depth = query.count('.')
            
            is_dga = entropy > 4.0 or length > 50
            is_deep = subdomain_depth > 5
            
            if is_dga or is_deep:
                findings.append(Finding(
                    title=f"Suspicious DNS Query from {src}",
                    description=f"Domain '{query}' has high entropy ({entropy:.2f}), length ({length}), or deep subdomains.",
                    severity=Severity.HIGH if is_dga else Severity.MEDIUM,
                    source_ip=src,
                    destination_ip=r.destination_ip,
                    protocol="dns",
                    detection_type="DNS Anomaly (DGA)" if is_dga else "DNS Anomaly",
                    timestamp=r.timestamp,
                    evidence={"query": query, "entropy": entropy, "length": length, "depth": subdomain_depth},
                    raw_data=r.raw_data
                ))

        # Check for excessive queries
        for src, queries in queries_by_src.items():
            if len(queries) > 100:
                findings.append(Finding(
                    title=f"Excessive DNS Queries from {src}",
                    description=f"Source {src} made {len(queries)} unique DNS queries.",
                    severity=Severity.MEDIUM,
                    source_ip=src,
                    detection_type="DNS Anomaly (Excessive)",
                    timestamp=latest_record_by_src[src].timestamp,
                    evidence={"unique_queries": len(queries)},
                    raw_data=latest_record_by_src[src].raw_data
                ))

        return findings
