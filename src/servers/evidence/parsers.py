import json
from typing import Iterator, Dict, Any
from .models import NormalizedEvent

def parse_zeek_ndjson(file_path: str) -> Iterator[NormalizedEvent]:
    """
    Parses a Zeek NDJSON file and yields NormalizedEvent objects.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                raw_data = json.loads(line)
                
                # Check for conn.log fields first
                if "id.orig_h" in raw_data and "id.resp_h" in raw_data:
                    yield NormalizedEvent(
                        timestamp=raw_data.get("ts", 0.0),
                        source_ip=raw_data["id.orig_h"],
                        source_port=raw_data.get("id.orig_p", 0),
                        destination_ip=raw_data["id.resp_h"],
                        destination_port=raw_data.get("id.resp_p", 0),
                        protocol=raw_data.get("proto", "unknown"),
                        service=raw_data.get("service"),
                        duration=raw_data.get("duration"),
                        bytes_sent=raw_data.get("orig_bytes"),
                        bytes_received=raw_data.get("resp_bytes"),
                        connection_state=raw_data.get("conn_state"),
                        raw_data=raw_data
                    )
                else:
                    # Depending on Zeek log type (dns, http, etc.), we might need different field mappings.
                    # For now, we assume conn-like fields if they exist, or skip if missing crucial routing data.
                    # As a fallback, try to extract basic info if available or log a warning.
                    pass
            except json.JSONDecodeError:
                # Log or handle parsing error
                pass
            except KeyError:
                # Handle missing mandatory fields
                pass

