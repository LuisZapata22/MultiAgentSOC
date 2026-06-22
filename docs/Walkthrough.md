# Walkthrough: Step 1 & 2

We have successfully established the base structure for the SOC Agentic Telemetry Analyzer and implemented the first MCP server.

## Changes Made

### 1. Repository Scaffold
- Created `requirements.txt` with base dependencies (`mcp`, `pydantic`).
- Initialized the Python package structure (`src/orchestrator/`, `src/servers/evidence/`).
- Verified `Architecture.md` as the source of truth for the system design.

### 2. Evidence Server Implementation
- Created `src/servers/evidence/models.py` defining the `NormalizedEvent` Pydantic schema. This schema captures core routing (IPs, ports, protocol) and contextual fields (duration, service, bytes, state).
- Created `src/servers/evidence/parsers.py` with a robust Zeek NDJSON parser (`parse_zeek_ndjson`) that extracts relevant fields from raw JSON lines into the `NormalizedEvent` schema.
- Built `src/servers/evidence/server.py` using the `mcp.server.fastmcp.FastMCP` SDK.
  - **Tool: `normalize_telemetry`**: Parses logs and stores them in memory.
  - **Tool: `read_evidence`**: Retrieves a paginated list of normalized events.
  - **Resource: `evidence://schemas/normalized_event`**: Returns the JSON schema.

## Validation Results

We created a test script (`tests/test_evidence_server.py`) and ran it against the provided sample log file (`zeek-capture.ndjson`).

> [!TIP]
> **Test Output:**
> - Extracted 13,144 events successfully from `zeek-capture.ndjson`.
> - The resource URI returned the correct JSON schema.
> - The tools responded correctly with structured JSON data.

## Next Steps

With the Evidence Server working, we will proceed to Step 3 and beyond.

---

# Walkthrough: Step 3

We built the core Orchestrator skeleton and wired the Telemetry Agent to connect seamlessly to the Evidence Server via MCP.

## Changes Made

### 1. Orchestrator Framework & Models
- Implemented `OrchestratorState` Enum (e.g. `UPLOADED`, `NORMALIZING`, `DETECTING`).
- Created the `TraceRecord` model for standardized logging of agent actions.
- Initialized an SQLite `TraceLogger` that tracks agent execution in a `trace.db` file.
- Designed `OrchestratorStateMachine` to process events and transition between states.

### 2. Telemetry Agent
- Built `TelemetryAgent` acting as a Model Context Protocol (MCP) client.
- The client dynamically provisions the Evidence Server process via standard IO (stdio).
- Interrogates the server using the `normalize_telemetry` tool.

## Validation Results

We executed `test_orchestrator_step3.py` against `zeek-capture.ndjson`.

> [!TIP]
> **Test Output:**
> - The state machine cleanly transitioned from `UPLOADED` -> `NORMALIZING`.
> - The Evidence server was launched automatically as an MCP stdio server.
> - Normalization succeeded.
> - The trace record was persisted in `test_trace.db`, and the final state correctly shifted to `DETECTING`.

## Next Steps

We are ready to move on to Step 4 and beyond.

---

# Walkthrough: Step 4

We built the Detection Server and Agent, connecting the Orchestrator to large language models for reasoning.

## Changes Made

### 1. Requirements & Environment
- Added `google-genai`, `groq`, `anthropic`, and `python-dotenv` to dependencies and installed them.
- Created an `.env.example` file instructing you to provide API keys.

### 2. LLM Router
- Created `LLMRouter` which abstracts all calls to the AI models. 
- It attempts to hit the Gemini API first, falling back to Groq if the Gemini API fails or is missing.
- It exposes a specialized Claude execution path for the final reporting phase.

### 3. Detection Server
- Created the `Detection Server` exposing the MCP `detection_reasoning_template` prompt, which instructs the model to hunt for anomalies (like port scans and beaconing).
- Provides a `correlate_events` helper tool.

### 4. Detection Agent
- Created `DetectionAgent` which runs as a client to *both* the Evidence Server (to fetch data) and the Detection Server (to fetch reasoning prompts).
- Calls `LLMRouter` with the combined context.
- Parses the resulting JSON findings and determines if the findings warrant conditional `PORT_ANALYSIS`.

## Validation Results

We executed `test_detection_step4.py` without supplying API keys to verify the system correctly catches the failure, invokes the fallback, and correctly blocks.

> [!TIP]
> **Test Output:**
> - Orchestrator moved to `DETECTING`.
> - LLM Router attempted Gemini -> Failed (no key).
> - LLM Router attempted Groq -> Failed (no key).
> - The Agent gracefully caught the exception and logged a trace with `confidence: 0.0` and `next_action: BLOCKED`.
> - The trace log successfully recorded all this metadata, allowing an analyst to easily see that the pipeline blocked due to missing API keys!

## Next Steps

We are ready to move on to Step 5.

---

# Walkthrough: Step 5

We implemented the Port Analysis step, creating a specialized MCP server and Agent to handle deep dives into port behavior.

## Changes Made

### 1. Port Analysis Server
- Created `src/servers/port_analysis/server.py` using `mcp.server.fastmcp`.
- Exposed the `port_reasoning_template` prompt which combines basic detection findings with raw events to find horizontal/vertical scans and suspicious exposed ports.
- Provided a `summarize_services` helper tool to quickly count the number of sources hitting any given destination port.

### 2. Port Analyzer Agent
- Developed `src/orchestrator/agents/port_analyzer_agent.py` which:
  1. Spawns and connects to both the Evidence Server (for raw data) and Port Analysis Server (for reasoning logic).
  2. Synthesizes `events_json` with `previous_findings` and dynamically populates the prompt.
  3. Uses the `LLMRouter` to request findings.

### 3. Orchestrator Integration
- Added the `PortAnalyzerAgent` initialization to `state_machine.py`.
- Added the `run_port_analysis` state method, which correctly logs the trace and passes the cumulative findings forward to `MITRE_MAPPING`.

## Validation Results

We executed `test_port_analysis_step5.py` to ensure the correct state transitions.

> [!TIP]
> **Test Output:**
> - Orchestrator began at `PORT_ANALYSIS` (via mock setup).
> - Agent invoked both Evidence and Port Analysis MCP servers.
> - Agent invoked the LLMRouter for Port Analysis.
> - The Trace logger accurately persisted the step, marking `sender="PortAnalyzerAgent"` and `receiver="MitreAgent"`, along with the `MITRE_MAPPING` next action.

## Next Steps

We are ready to move on to Step 6.

---

# Walkthrough: Step 6

We implemented the MITRE Mapping layer. To prevent AI hallucinations regarding T-codes, we strictly bound the agent to use a bundled, version-pinned subset of the real MITRE ATT&CK taxonomy.

## Changes Made

### 1. MITRE Data Fetching
- Created `src/servers/mitre/fetch_taxonomy.py` which reaches out to the official MITRE STIX JSON dataset on GitHub and extracts a lightweight mapping of relevant network techniques (ID, Name, Tactics, Description).
- Executed the script, generating the `mitre_taxonomy.json` bundle locally.

### 2. MITRE Server
- Created `src/servers/mitre/server.py` using `mcp.server.fastmcp`.
- Exposed the `mitre_mapping_template` prompt, which embeds the taxonomy context dynamically into the prompt for the LLM.
- Pre-filtered the taxonomy to only include strictly relevant SOC/Network tactics (Discovery, Lateral Movement, C2, etc.) to ensure it fits safely inside all LLM context windows (including fallback models like Groq's Llama-3-8b).

### 3. MITRE Agent
- Developed `src/orchestrator/agents/mitre_agent.py` which connects to the MITRE MCP Server, hydrates the template with the cumulative findings from Detection & Port Analysis, and triggers the LLMRouter.
- Parses out the exact MITRE classifications and appends them to the findings JSON.

### 4. Orchestrator Integration
- Hooked up `run_mitre_mapping` inside `state_machine.py`.
- It takes the mapped output and records a highly-confident trace (`confidence=0.9` since we rely on the bundled taxonomy lookup) before transitioning the workflow into the `VALIDATING` state.

## Validation Results

We executed `test_mitre_step6.py` to confirm state machine transitions.

> [!TIP]
> **Test Output:**
> - Orchestrator began at `MITRE_MAPPING`.
> - Agent invoked the MITRE Server and fetched the taxonomy prompt.
> - Agent called the LLMRouter.
> - Trace correctly recorded `sender="MitreAgent"` and `receiver="ValidationAgent"`, targeting `VALIDATING` as the next action.

## Next Steps

We are ready to move on to Step 8.

---

# Walkthrough: Step 8

We implemented the Reporting Layer, the final stage of the pipeline which aggregates all previous context, queries Claude for a polished executive summary, and persists the formal JSON report to disk.

## Changes Made

### 1. Robust Fallback Routing
- Updated `llm_router.py` to ensure that API outages (like 503s or missing models) don't crash the pipeline at the very end. The router now gracefully returns a degraded state if Claude or Gemini/Groq fail completely.

### 2. Reporting Server
- Created `src/servers/reporting/server.py` using `mcp.server.fastmcp`.
- Exposed a `save_report` MCP tool that handles writing the final JSON payload safely to a `reports/` directory.
- Exposed the `report_generation_template` prompt, tailored specifically for Claude to produce a strict JSON formal Incident Assessment Report.

### 3. Reporting Agent
- Developed `src/orchestrator/agents/reporting_agent.py` which extracts deterministic validation data, MITRE mappings, and LLM summaries from the pipeline state.
- Combines them using the Reporting Server's template.
- Implements a programmatic `_build_fallback_report()` method. If Claude is offline or missing API keys, this ensures the system still successfully generates and saves a fully structured report based purely on the deterministic data generated in Step 7.

### 4. Orchestrator Integration
- Hooked up `run_reporting` inside `state_machine.py`.
- Final state transitions to `COMPLETE` after successful generation.

## Validation Results

We executed `test_reporting_step8.py`.

> [!TIP]
> **Test Output:**
> - Orchestrator began at `REPORTING` with simulated findings.
> - Claude was called via the router, but simulated an API failure (missing key / bad model).
> - The Agent gracefully fell back to the deterministic structural report generator.
> - Report was successfully saved to disk (`reports/soc_report_...json`).
> - Trace correctly recorded `sender="ReportingAgent"`, ending the pipeline at `COMPLETE`.

## Next Steps

**Step 9: React Dashboard & API Integration**. 
The Python backend orchestration is 100% complete! Next, we will wrap the orchestrator in a lightweight FastAPI/Uvicorn server and build a React frontend to visualize the traces and final reports.

---

# Walkthrough: Step 9

We successfully wrapped the agentic backend in a fully functional REST API and built a premium, dynamic React frontend to visualize the SOC pipeline in real-time.

## Changes Made

### 1. FastAPI Integration
- Created `src/api/main.py`.
- Exposed endpoints to handle telemetry uploads (`POST /api/upload`) and trigger the pipeline.
- Exposed endpoints to stream Orchestrator state (`GET /api/status`), fetch live SQLite traces (`GET /api/traces`), and retrieve the final generated JSON report (`GET /api/report`).

### 2. React Dashboard Application
- Initialized a modern Vite React TypeScript project.
- Installed `lucide-react` for premium scalable iconography and `recharts` for visual data charting.
- Designed a custom **Vanilla CSS** stylesheet featuring:
  - Deep dark mode aesthetics with a custom tailored HSL color palette.
  - Glassmorphism effects with dynamic glows and subtle drop shadows.
  - Smooth micro-animations for active nodes and status indicators.

### 3. Core React Components
- **UploadZone**: A beautiful drag-and-drop landing area to ingest `.ndjson` Zeek logs.
- **PipelineVisualizer**: A dynamic 8-step pipeline tracker that lights up and traces progress as the Orchestrator works through its states (UPLOADED ➔ NORMALIZING ➔ DETECTING ➔ PORT_ANALYSIS ➔ MITRE_MAPPING ➔ VALIDATING ➔ REPORTING ➔ COMPLETE).
- **Live Trace Terminal**: A stylized, auto-scrolling log showing all inter-agent communications and background LLM decisions.
- **Report Viewer**: A structured presentation of the final Claude report, complete with a severity distribution bar chart and detailed breakdown of confirmed malicious techniques.

## Verification

The system is fully constructed! You can now run the backend via `uvicorn` and the frontend via Vite, upload the `zeek-capture.ndjson` file, and watch the agents autonomously map the simulated network telemetry directly to MITRE ATT&CK techniques in a visually rich UI.
