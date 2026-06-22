# Architecture: SOC Agentic Telemetry Analyzer

## 1. Purpose and scope

This document defines the system architecture for the SOC Agentic Telemetry Analyzer: a defensive, proof-of-concept multi-agent platform that ingests network telemetry (Zeek, ntopng, JSON, CSV), detects suspicious behavior, maps findings to MITRE ATT&CK, validates evidence support, and produces a human-reviewable report.

The system performs no offensive actions, no autonomous exploitation, and no automated remediation. Every output is advisory and intended for review by a human SOC analyst.

## 2. Layered architecture

The system is organized into four layers, in line with the project's original design intent.

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: MCP Host (React Dashboard)                          │
│  - Upload telemetry, view live trace, review findings,       │
│    respond to elicitation, approve final report               │
└───────────────────────┬─────────────────────────────────────┘
                         │ HTTP/WebSocket
┌───────────────────────▼─────────────────────────────────────┐
│ Layer 2: Orchestrator (Python)                                │
│  - Owns analysis state machine                                │
│  - Routes agent-to-agent flow                                 │
│  - Acts as MCP client to all six servers                      │
│  - Persists structured exchange trace                         │
│  - Selects and falls back between LLM providers                │
└───────────────────────┬─────────────────────────────────────┘
                         │ MCP (stdio / SSE)
┌───────────────────────▼─────────────────────────────────────┐
│ Layer 3: MCP Servers (six independent processes)              │
│  Evidence │ Detection │ Port Analysis │ MITRE │ Validation │   │
│  Reporting                                                     │
└───────────────────────┬─────────────────────────────────────┘
                         │ invoked by
┌───────────────────────▼─────────────────────────────────────┐
│ Layer 4: Specialized Agents (six)                              │
│  Telemetry │ Detection │ Port Analyzer │ MITRE │ Validation │  │
│  Report                                                         │
└─────────────────────────────────────────────────────────────┘
```

Each layer only talks to the layer immediately adjacent to it. The Orchestrator never bypasses MCP to call a server's internal logic directly, and no agent reaches across to a server outside its own domain (e.g. the MITRE Agent never calls the Validation Server directly — that hop goes through the Orchestrator).

## 3. Orchestration approach

**Choice: custom state-machine orchestrator, not LangGraph.**

Rationale: the analysis pipeline is a fixed, mostly-linear sequence (Telemetry → Detection → [Port Analyzer, conditional] → MITRE → Validation → Report) with one conditional branch and no cyclical agent negotiation. LangGraph earns its complexity when agents need to loop, re-plan, or call each other dynamically; here the flow is known at design time and traceability to a human analyst matters more than flexible graph routing. A explicit state machine is easier to reason about, easier to defend in an academic review, and makes the "next action" field in the trace log a direct reflection of code rather than an LLM-driven graph decision.

The state machine is implemented as a single Python class (`OrchestratorStateMachine`) with explicit states:

```
UPLOADED → NORMALIZING → DETECTING → (PORT_ANALYSIS)? → MITRE_MAPPING
  → VALIDATING → REPORTING → AWAITING_APPROVAL → COMPLETE
```

Each state transition:
1. Calls the relevant agent, which in turn calls its MCP server(s) for tools/resources and an LLM provider for reasoning.
2. Writes a structured trace record (see §6).
3. Evaluates a transition condition (e.g. "does Detection output contain port-related signals?" before deciding whether to enter `PORT_ANALYSIS`).
4. Emits a state update over WebSocket to the React host so the live trace view updates in real time.

If a state's agent call fails after retries (including LLM provider fallback, §5), the state machine transitions to a `BLOCKED` state and raises an elicitation request to the host rather than guessing or proceeding on incomplete data.

## 4. MCP layer

All six servers are independent OS processes implemented with the official `mcp` Python SDK, communicating over stdio when run locally and SSE when deployed as long-running services. They are never merged into a single process — this is a hard constraint from the project spec, since simulating multiple servers in one process would undermine the modularity and defensibility the architecture is meant to demonstrate.

| Server | Resources | Tools | Prompts |
|---|---|---|---|
| Evidence | raw logs, normalized events, schemas | `read_evidence`, `normalize_telemetry`, `extract_fields`, `filter_time_range` | normalization templates per log source |
| Detection | intermediate detection results | `detect_anomalies`, `correlate_events`, `score_risk`, `explain_pattern` | detection reasoning templates |
| Port Analysis | port/service summaries | `analyze_ports`, `identify_scans`, `detect_unusual_port_usage`, `summarize_services` | port-analysis reasoning templates |
| MITRE | ATT&CK technique/tactic dataset | `map_to_mitre`, `find_related_tactics`, `link_techniques`, `estimate_mitre_coverage` | mapping-explanation templates |
| Validation | evidence cross-reference index | `validate_finding`, `cross_check_evidence`, `compute_confidence`, `detect_inconsistencies` | validation reasoning templates |
| Reporting | report drafts, prior reports | `generate_report_md`, `export_pdf`, `generate_executive_summary`, `suggest_mitigations` | report-writing templates |

The MITRE Server bundles a static, version-pinned copy of the ATT&CK Enterprise dataset (technique IDs, tactic IDs, names, descriptions) rather than fetching it live. This keeps the demo reproducible offline and avoids the MITRE Agent ever inventing a technique ID — every mapping is a lookup against real data, not a generative claim.

## 5. LLM provider strategy

Three providers are used, each for a distinct reason, not interchangeably:

| Stage | Primary | Fallback | Why |
|---|---|---|---|
| Detection Agent | Gemini API | Groq | High-volume reasoning over normalized event batches; cost/throughput matters more than peak nuance |
| Port Analyzer Agent | Gemini API | Groq | Same — structured, pattern-matching-style reasoning |
| MITRE ATT&CK Agent | Gemini API | Groq | Mapping against a fixed taxonomy; well within Gemini's reliability range |
| Validation Agent | Gemini API | Groq | Cross-checking evidence references; structured, rule-like reasoning |
| Report Agent | **Claude API** | *(none — see below)* | Final document is the one artifact a human reads end-to-end; prioritizes writing quality, calibrated language about confidence, and faithful synthesis over raw throughput |

### Rationale

Gemini is the default reasoning engine for the four mid-pipeline agents because these stages run frequently, often over large normalized event batches, and their output is structured (findings, scores, mappings) rather than long-form prose — a good fit for a fast, cost-efficient primary model. Groq serves purely as an availability fallback for those same four agents: if a Gemini call fails, times out, or is rate-limited, the Orchestrator retries the identical prompt against a Groq-hosted model before giving up and raising a `BLOCKED` state. Groq is not used as a quality upgrade or alternative reasoning path — it exists to keep the pipeline from stalling on a single provider's outage, and its output is treated as equivalent-but-not-preferred.

Claude is used exclusively for the Report Agent, with no automatic fallback to Gemini or Groq for that stage. The Report Agent's job — synthesizing six stages of upstream findings, evidence, and confidence scores into a technical report and an executive summary that a human analyst and stakeholders will actually read — depends on long-context synthesis and calibrated, non-overclaiming language about uncertainty. If the Claude call fails, the Orchestrator does not silently substitute another provider for this stage; it surfaces the failure to the host as a `BLOCKED` state and lets the analyst decide whether to retry, since a degraded final report is worse than a delayed one. This is a deliberate asymmetry: cost-optimize the high-volume middle stages, do not cost-optimize the one document a human will sign off on.

### Provider abstraction

All LLM calls go through a single `LLMRouter` interface in the Orchestrator, not directly from each agent:

```python
class LLMRouter:
    def call(self, stage: str, prompt: str, **kwargs) -> LLMResponse:
        # stage in {"detection", "port_analysis", "mitre", "validation"}: Gemini -> Groq fallback
        # stage == "report": Claude only, no fallback
        ...
```

This keeps provider selection, retry logic, and fallback policy in one place rather than scattered across six agent implementations, and makes it straightforward to change the provider mapping later without touching agent code. Each call is logged with provider used, latency, and whether a fallback was triggered, feeding into the same structured trace described in §6.

### Required environment variables

```
GEMINI_API_KEY=
GROQ_API_KEY=
ANTHROPIC_API_KEY=
```

The system should fail fast at startup if any of these are missing, rather than discovering a missing key mid-pipeline.

## 6. Trace and state model

Every agent-to-agent exchange produces a structured record:

```json
{
  "sender": "DetectionAgent",
  "receiver": "PortAnalyzerAgent",
  "task": "analyze_port_behavior",
  "evidence_used": ["evt_00231", "evt_00245"],
  "result": { "...": "..." },
  "confidence": 0.62,
  "next_action": "MITRE_MAPPING",
  "llm_provider": "gemini",
  "fallback_triggered": false,
  "timestamp": "2026-06-21T14:03:11Z"
}
```

These records are persisted (SQLite for the proof of concept) and streamed to the React host over WebSocket so the live trace view reflects the pipeline as it runs, not just at completion. This trace is also what the Validation Agent and Report Agent read back from — findings are never passed forward as bare LLM output without their originating evidence references attached.

## 7. Data flow summary

1. Analyst uploads telemetry via the React host.
2. Orchestrator enters `NORMALIZING`; Telemetry Agent calls the Evidence Server to parse and normalize Zeek/ntopng/JSON/CSV input into a common event schema.
3. Orchestrator enters `DETECTING`; Detection Agent calls the Detection Server's tools, reasoning via Gemini (Groq fallback).
4. If Detection output contains port-related signals, Orchestrator enters `PORT_ANALYSIS`; Port Analyzer Agent calls the Port Analysis Server, same provider policy.
5. Orchestrator enters `MITRE_MAPPING`; MITRE Agent calls the MITRE Server against the bundled ATT&CK dataset.
6. Orchestrator enters `VALIDATING`; Validation Agent calls the Validation Server, assigns confidence, flags unsupported findings.
7. Orchestrator enters `REPORTING`; Report Agent calls the Reporting Server, reasoning via Claude only, producing technical report + executive summary.
8. Orchestrator enters `AWAITING_APPROVAL`; analyst reviews in the React host and approves or requests changes.
9. Orchestrator enters `COMPLETE`.

## 8. Constraints carried into implementation

- No server's logic leaks into another (e.g. MITRE mapping logic lives only in the MITRE Server).
- No agent asserts a finding without an attached evidence reference and confidence score.
- No offensive tooling, exploit generation, or automated remediation actions anywhere in the codebase.
- Fallback policy is asymmetric by design: cost-optimized with fallback for Detection/Port/MITRE/Validation, quality-optimized with no fallback for Report.