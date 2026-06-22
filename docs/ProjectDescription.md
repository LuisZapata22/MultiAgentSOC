## Project Summary: SOC Agentic Telemetry Analyzer Based on MCP

This project evolves an original **SOC telemetry dashboard** into a **multi-agent security analysis platform** built around the **Model Context Protocol (MCP)**. The original version of the project focused on collecting and visualizing network telemetry from sources such as Zeek, ntopng, and JSON logs, with the goal of helping a SOC analyst inspect traffic, detect suspicious behavior, and produce security findings. In the new version, the dashboard becomes an **agentic workflow**, where several specialized AI agents collaborate to process evidence, detect anomalies, validate findings, map them to MITRE ATT&CK, and generate a final security report.

The core idea is to replace a single monolithic analysis flow with a **modular architecture** in which each agent has a clear responsibility. MCP is used as the standard layer that connects the AI system to external tools, evidence, and structured prompts. According to the official MCP documentation, servers expose **tools**, **resources**, and **prompts**, while clients can support **elicitation**, **sampling**, and other interaction features. MCP is a JSON-RPC–based protocol designed to connect AI applications to external systems and context sources in a standardized way. ([Model Context Protocol][1])

### Main purpose of the project

The project aims to build a **proof of concept** for a defensive SOC assistant that can:

* ingest telemetry and logs,
* analyze network behavior,
* detect possible threats or anomalies,
* classify findings using MITRE ATT&CK,
* validate evidence before conclusions are accepted,
* and generate a structured final report for a human analyst.

The system is designed for **defensive analysis only**. It does not perform offensive actions, autonomous exploitation, or unsafe remediation. Its role is to support analysts by explaining what was observed, why it matters, how confident the system is, and what defensive actions are recommended.

### Proposed architecture

The new architecture is organized into four layers:

**1. MCP Host**
This is the user-facing application, such as a web dashboard or CLI. The analyst uploads telemetry, reviews findings, requests clarification, and approves the final report. The host can also support interactive requests for missing context through MCP elicitation when needed. ([Model Context Protocol][2])

**2. Orchestrator**
This internal layer coordinates the agents. It assigns tasks, routes outputs from one agent to the next, tracks the analysis state, and ensures that the conversation remains structured. The orchestrator is not MCP itself; instead, it manages the collaboration logic while MCP provides standardized access to evidence and tools. That separation fits MCP’s client-server model, where the protocol defines the exchange of context and capabilities, but not the entire business logic of agent-to-agent coordination. ([Model Context Protocol][3])

**3. MCP Servers**
Instead of one large server, the system can be split into multiple specialized MCP servers. Each server exposes a focused set of resources, prompts, and tools for one stage of the analysis. MCP resources are identified by URI and are intended to share contextual data such as files, schemas, or application-specific information. Tools let models call external functions, while prompts provide reusable workflow templates. ([Model Context Protocol][4])

**4. Specialized Agents**
Each agent consumes outputs from the previous stage, performs one job well, and passes structured results forward.

---

## Agents in the new structure

### 1. Telemetry Agent

This agent is responsible for reading raw evidence and converting it into a usable format. It processes logs from Zeek, ntopng, JSON event files, CSV exports, and other telemetry sources. Its job is to normalize fields, extract timestamps, ports, IPs, protocols, and service data, and produce a clean event stream for downstream analysis.

### 2. Detection Agent

This agent analyzes the normalized telemetry and looks for suspicious patterns. It can identify unusual connection volumes, repeated port scans, abnormal protocol use, beaconing-like behavior, failed connections, or traffic spikes. It transforms raw events into technical findings.

### 3. Port Analyzer Agent

This is a specialized detector focused on port-related behavior. It examines:

* open or frequently used ports,
* uncommon port usage,
* repeated connection attempts to many destinations,
* horizontal or vertical scanning patterns,
* service exposure and suspicious port combinations.

This is especially useful in a SOC context because port behavior often reveals reconnaissance, scanning, lateral movement, or misconfiguration.

### 4. MITRE ATT&CK Agent

This agent maps technical findings to relevant MITRE ATT&CK tactics and techniques. For example, it can relate repeated port probing to discovery or reconnaissance behavior, or suspicious internal movement to lateral movement patterns. Its role is not only classification, but also explanation: it helps the report communicate why a finding matters in attacker-behavior terms.

### 5. Validation Agent

This agent checks whether each finding is supported by enough evidence. It prevents unsupported conclusions, reduces hallucinations, and assigns a confidence score to each result. If evidence is insufficient, the agent can mark the finding as weak, incomplete, or unconfirmed.

### 6. Report Agent

This agent consolidates the results into a final document. It prepares both:

* a **technical report** for analysts, and
* an **executive summary** for stakeholders.

It includes findings, evidence references, MITRE mapping, confidence levels, and recommendations.

---

## MCP servers and their specific responsibilities

### Evidence Server

Handles ingestion and retrieval of telemetry evidence. It can expose resources such as:

* raw logs,
* normalized events,
* schemas,
* evidence bundles,
* intermediate analysis results.

Example tools:

* `read_evidence()`
* `normalize_telemetry()`
* `extract_fields()`
* `filter_time_range()`

### Detection Server

Provides analysis utilities for anomaly and pattern detection.

Example tools:

* `detect_anomalies()`
* `correlate_events()`
* `score_risk()`
* `explain_pattern()`

### Port Analysis Server

Focuses specifically on port behavior and network exposure.

Example tools:

* `analyze_ports()`
* `identify_scans()`
* `detect_unusual_port_usage()`
* `summarize_services()`

### MITRE Server

Maps findings to ATT&CK techniques and tactics.

Example tools:

* `map_to_mitre()`
* `find_related_tactics()`
* `link_techniques()`
* `estimate_mitre_coverage()`

### Validation Server

Checks consistency, evidence support, and confidence.

Example tools:

* `validate_finding()`
* `cross_check_evidence()`
* `compute_confidence()`
* `detect_inconsistencies()`

### Reporting Server

Builds the final document and exports it.

Example tools:

* `generate_report_md()`
* `export_pdf()`
* `generate_executive_summary()`
* `suggest_mitigations()`

MCP’s tool system is a natural fit for these functions because the official specification describes tools as model-invokable server functions for tasks like querying data, calling APIs, and performing computations. MCP resources are suitable for exposing evidence and context, and prompts are suitable for reusable analysis workflows. ([Model Context Protocol][5])

---

## How the agents work together

The collaboration flow is structured and traceable:

1. The analyst uploads telemetry to the MCP Host.
2. The Orchestrator sends the evidence to the Telemetry Agent.
3. The Telemetry Agent uses the Evidence Server to load and normalize the data.
4. The Detection Agent receives the processed events and identifies suspicious patterns.
5. The Port Analyzer Agent performs deeper inspection of port behavior when needed.
6. The MITRE ATT&CK Agent maps the findings to tactics and techniques.
7. The Validation Agent checks whether the findings are sufficiently supported.
8. The Report Agent generates the final document.
9. The analyst reviews the result and approves it.

To keep the interaction realistic, each agent exchange should be structured, for example:

* sender,
* receiver,
* task,
* evidence used,
* result,
* confidence,
* next action.

This gives the project traceability and makes the AI collaboration visible during the defense.

---

## Analyzers available in the project

The system can include several analyzers, depending on the evidence available. The most relevant ones are:

* **Port analyzers**: inspect port activity, scans, and service exposure.
* **Log analyzers**: parse Zeek or JSON logs and extract useful indicators.
* **Traffic analyzers**: summarize flow patterns and connection behavior.
* **Anomaly analyzers**: detect outliers, spikes, and unusual activity.
* **MITRE ATT&CK analyzers**: map findings to techniques and tactics.
* **Risk classifiers**: assign severity or priority to each finding.
* **Validation analyzers**: check whether the evidence actually supports the claim.
* **Report analyzers**: transform the analysis into a structured report.

These analyzers can be implemented as tools inside different MCP servers, allowing the agents to request only the capabilities they need for each step.

---

## Why this structure is strong for the project

This design is strong because it is:

* **modular**: each agent has one clear role,
* **traceable**: every finding is supported by evidence,
* **defensive**: it avoids unsafe autonomous actions,
* **realistic**: it mirrors how security teams separate detection, validation, and reporting,
* **MCP-aligned**: it uses resources, tools, prompts, and elicitation in the way MCP is intended to be used. ([Model Context Protocol][3])

## Final description

In summary, the project is a **SOC agentic telemetry analysis platform** that transforms a traditional dashboard into a multi-agent security assistant. The original system focused on visual inspection of telemetry; the new version adds collaboration between specialized AI agents, each backed by focused MCP servers and analyzers. The result is a practical proof of concept where evidence is collected, analyzed, validated, mapped to MITRE ATT&CK, and reported in a structured way that is suitable for academic evaluation and realistic security operations.

[1]: https://modelcontextprotocol.io/docs/getting-started/intro?utm_source=chatgpt.com "Model Context Protocol"
[2]: https://modelcontextprotocol.io/specification/draft/client/elicitation?utm_source=chatgpt.com "Elicitation"
[3]: https://modelcontextprotocol.io/docs/learn/architecture?utm_source=chatgpt.com "Architecture overview"
[4]: https://modelcontextprotocol.io/specification/2025-06-18/server/resources?utm_source=chatgpt.com "Resources"
[5]: https://modelcontextprotocol.io/specification/2025-06-18/server/tools?utm_source=chatgpt.com "Tools"
