import json
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MITRE")

TAXONOMY_FILE = os.path.join(os.path.dirname(__file__), "mitre_taxonomy.json")

def load_taxonomy():
    if not os.path.exists(TAXONOMY_FILE):
        return {}
    with open(TAXONOMY_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

TAXONOMY = load_taxonomy()

# Pre-filter relevant tactics to save context window for LLMs like Groq
RELEVANT_TACTICS = {
    "mitre-discovery",
    "mitre-lateral-movement",
    "mitre-command-and-control",
    "mitre-exfiltration",
    "mitre-initial-access",
    "mitre-credential-access"
}

def get_filtered_taxonomy():
    filtered = {}
    for tid, info in TAXONOMY.items():
        tactics = info.get("tactics", [])
        if any(t in RELEVANT_TACTICS for t in tactics):
            filtered[tid] = {
                "name": info["name"],
                "tactics": tactics
            }
    return filtered

@mcp.tool()
def get_technique_details(technique_id: str) -> str:
    """
    Returns the full details (including description) of a specific MITRE ATT&CK technique.
    
    Args:
        technique_id: The ID of the technique (e.g., 'T1059').
    """
    if technique_id in TAXONOMY:
        return json.dumps(TAXONOMY[technique_id])
    return f"Technique {technique_id} not found."

@mcp.prompt()
def mitre_mapping_template(findings_json: str) -> str:
    """
    Returns the reasoning template for the MITRE Agent.
    
    Args:
        findings_json: JSON string of the findings from previous stages.
    """
    filtered_tax = get_filtered_taxonomy()
    
    prompt = f"""You are a specialized SOC MITRE ATT&CK Mapping Expert.
Review the following technical findings identified by previous detection layers.
Your goal is to map these findings to formal MITRE ATT&CK Enterprise techniques.

Technical Findings:
{findings_json}

Available Network-Relevant MITRE Taxonomy (ID -> Name/Tactic):
{json.dumps(filtered_tax, indent=2)}

For each finding, identify the single most relevant MITRE Technique ID. 
If no technique applies, return an empty string for the technique_id.

Output your findings as a strict JSON array of objects, where each object has:
- "original_finding": The original finding string.
- "mitre_technique_id": The chosen technique ID (e.g. "T1046").
- "mitre_tactic": The tactic (e.g. "mitre-discovery").
- "justification": A brief sentence explaining why this mapping is correct based on the evidence.

Return ONLY the JSON array.
"""
    return prompt

@mcp.resource("mitre://taxonomy")
def get_taxonomy() -> str:
    """
    Returns the full bundled MITRE taxonomy.
    """
    return json.dumps(TAXONOMY)

if __name__ == "__main__":
    mcp.run(transport='stdio')
