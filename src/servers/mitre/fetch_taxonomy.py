import urllib.request
import json
import os

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "mitre_taxonomy.json")

def fetch_and_parse():
    print(f"Fetching MITRE ATT&CK STIX data from {STIX_URL}...")
    req = urllib.request.Request(STIX_URL, headers={'User-Agent': 'Mozilla/5.0'})
    
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode('utf-8'))
        
    print("Parsing STIX data...")
    taxonomy = {}
    
    # The STIX json contains a 'objects' list
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            # Extract MITRE ID from external_references
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break
            
            if mitre_id:
                # Extract tactics from kill_chain_phases
                tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase.get("phase_name"))
                
                # Keep descriptions brief (first paragraph)
                description = obj.get("description", "").split("\n")[0]
                
                taxonomy[mitre_id] = {
                    "name": obj.get("name"),
                    "description": description,
                    "tactics": tactics
                }
                
    print(f"Extracted {len(taxonomy)} techniques.")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(taxonomy, f, indent=2)
        
    print(f"Saved taxonomy to {OUTPUT_FILE}")

if __name__ == "__main__":
    fetch_and_parse()
