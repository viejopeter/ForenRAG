# ForenRAG

**An Event-Driven Retrieval-Augmented Framework for Provenance-Oriented Post-Alert Digital Forensic Investigation**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22088854.svg)](https://doi.org/10.5281/zenodo.22088854)

ForenRAG is a research prototype for automated post-alert digital forensic investigation in a controlled Windows laboratory. It receives high-severity Wazuh alerts, correlates them with Sysmon telemetry in OpenSearch, creates a structured evidence package, retrieves technique-relevant defensive knowledge from a local ChromaDB index, and uses a locally hosted Ollama model to produce a Markdown forensic report.

The framework supports inspection and repeatable laboratory evaluation of post-detection evidence collection and report generation. It is not a production incident-response platform, and model-generated conclusions must be reviewed by a qualified analyst.

## Scope

ForenRAG implements four main stages:

1. Receive a qualifying Wazuh alert and group related activity during a settling window.
2. Correlate Sysmon process, file-creation, and registry telemetry from OpenSearch.
3. Create a structured evidence package and retrieve technique-relevant local knowledge.
4. Generate a report with local Ollama reasoning and deterministic evidence sections.

The current telemetry scope is limited to Wazuh alerts and Sysmon Event IDs 1, 11, and 13. ForenRAG does not collect network connections, process exit status, file deletion, memory images, packet captures, or command return codes. It also has no live CVE retrieval, previous-case repository, or general network-event collector.

## Architecture

```text
Windows endpoint
  Sysmon EID 1, 11, 13
          |
          v
Wazuh Agent -> Wazuh Manager / OpenSearch
                          |             |
                    POST /alert    alert poller
                          \             /
                           v           v
                    alert session grouping
                    and settling window
                              |
                              v
                  OpenSearch archive queries
                  process tree + artifacts
                              |
                              v
                         evidence.json
                              |
              +---------------+----------------+
              |                                |
              v                                v
       ChromaDB retrieval               structured evidence
       Ollama embeddings                       |
              |                                |
              +---------------+----------------+
                              v
                     local Ollama reasoning
                              |
                              v
                   deterministic post-processing
                              |
                              v
                      forensic_report.md
```

### Components

| Component | Responsibility |
|---|---|
| `app.py` | Flask API, OpenSearch polling, alert grouping, process and artifact collection, evidence persistence, and asynchronous report triggering |
| `build_chroma_db.py` | Knowledge loading, metadata extraction, chunking, Ollama embedding, and full ChromaDB rebuild |
| `forenrag_retriever.py` | Evidence-derived query construction, metadata-filtered vector search, fallback search, and lexical reranking |
| `forenrag_reasoner.py` | Evidence formatting, prompt construction, Ollama inference, deterministic report sections, and latency persistence |
| `technique_inference.py` | Normalization of detector-supplied ATT&CK labels and scenario-specific T1105 inference from correlated GUP activity |
| `knowledge_base/` | Local Markdown and YAML sources used to build the retrieval index |
| `study_dataset/` | Sanitised trial-level timing, collector-validation, retrieval, phase-duration, and report-grounding data supporting the manuscript |

## Requirements

### Analysis Host

- Python 3.12 or newer
- [`uv`](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/)
- Network access to the laboratory OpenSearch endpoint
- Sufficient local storage for ChromaDB and generated evidence packages
- Sufficient RAM or accelerator capacity for the selected Ollama model

### Telemetry Environment

- A Windows endpoint with Sysmon configured to collect Event IDs 1, 11, and 13
- A Wazuh Agent forwarding the endpoint telemetry
- Wazuh Manager and OpenSearch with both alert and archive indexing enabled
- OpenSearch indexes matching `wazuh-alerts-*` and `wazuh-archives-*`
- Credentials authorized to search those index patterns

Raw archive indexing is required. Alert records alone do not contain enough information for process-tree and artifact correlation.

### Local Models

The supplied configuration uses:

- `nomic-embed-text` for embeddings
- `gemma4:e2b` for report generation

Model tags are configurable. Changing the embedding model requires rebuilding the Chroma index.

## Laboratory Setup

ForenRAG assumes three logical roles:

1. A Windows victim VM running Sysmon, Wazuh Agent, PowerShell, and Atomic Red Team.
2. An Ubuntu security VM running Wazuh Manager and its OpenSearch-compatible indexer.
3. An analysis host running ForenRAG, ChromaDB, and Ollama.

Use an isolated virtual network and take clean snapshots before executing adversary-emulation scenarios. Exact installation commands can change between releases, so use the official documentation for the versions selected for the laboratory.

Install Atomic Red Team and its PowerShell execution module on the Windows victim by following the official [Invoke-AtomicRedTeam getting-started guide](https://www.atomicredteam.io/docs/invoke-atomicredteam/getting-started). The evaluated scenario commands require `Invoke-AtomicTest`; run tests that require administrator privileges from an elevated PowerShell session.

### 1. Install the Wazuh Server

On the Ubuntu security VM, install the Wazuh server components using the official [Wazuh installation assistant](https://documentation.wazuh.com/current/installation-guide/wazuh-server/installation-assistant.html). The deployment must provide:

- Wazuh Manager for agent enrollment and rule evaluation
- Wazuh Indexer or an equivalent OpenSearch endpoint
- Filebeat or the Wazuh-supported forwarding path between the manager and indexer
- HTTPS REST access from the ForenRAG analysis host to port `9200`

Use a least-privilege OpenSearch account for ForenRAG where possible.

### 2. Enable Wazuh Archive Events

ForenRAG queries `wazuh-archives-*` for raw Sysmon records. On the Wazuh Manager, enable JSON archive logging in `/var/ossec/etc/ossec.conf`:

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall_json>yes</logall_json>
</global>
```

Enable archive forwarding in the Wazuh Filebeat configuration for the installed version. A typical setting is:

```yaml
archives:
  enabled: true
```

Restart the Wazuh Manager and Filebeat after validating their configuration. Archive indexing increases storage consumption because it retains events that do not generate alerts; configure retention and disk monitoring before testing.

Confirm that both index patterns exist after endpoint telemetry arrives:

```bash
curl -k -u '<OPENSEARCH_USERNAME>:<OPENSEARCH_PASSWORD>' \
  'https://<OPENSEARCH_HOST>:9200/_cat/indices/wazuh-alerts-*,wazuh-archives-*?v'
```

### 3. Install Sysmon on the Windows VM

Download Sysmon from the official [Microsoft Sysinternals Sysmon page](https://learn.microsoft.com/sysinternals/downloads/sysmon). Use a reviewed Sysmon XML policy that records at least:

- Event ID 1: Process creation
- Event ID 11: File creation
- Event ID 13: Registry value modification

From an elevated PowerShell session, install Sysmon with the selected policy:

```powershell
Sysmon64.exe -accepteula -i C:\Lab\sysmon-config.xml
```

To update the policy later:

```powershell
Sysmon64.exe -c C:\Lab\sysmon-config.xml
```

Verify the service and event channel:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5
```

### 4. Install and Enroll the Wazuh Agent

Install the Windows agent using the official [Wazuh Windows agent guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html). Configure the agent with the Wazuh Manager address, enroll it, and start the service. The exact MSI filename and enrollment options depend on the selected Wazuh release.

Ensure the agent collects the Sysmon operational channel. The Windows agent configuration in `C:\Program Files (x86)\ossec-agent\ossec.conf` should include:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart and verify the agent from an elevated PowerShell session:

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

Confirm on the manager that the agent is connected and record its agent ID. Set that value as `WAZUH_AGENT_ID` in the ForenRAG `.env` file.

### 5. Configure Detection and Alert Delivery

Wazuh must generate qualifying alerts for the selected scenarios. Install or create laboratory rules that map the relevant Sysmon activity to the expected ATT&CK technique identifiers and use a level at or above `MIN_RULE_LEVEL`. Detection rules are deployment-specific and are not bundled with this repository.

ForenRAG can receive alerts in either of two ways:

- The built-in poller reads recent records from `wazuh-alerts-*`.
- Wazuh or an integration service can send the full Wazuh alert JSON to `POST http://<FORENRAG_HOST>:5000/alert`.

The alert poller always starts with `app.py`. Webhook delivery is optional and additive; sending the same alert through both paths can produce duplicate processing.

### 6. Network Requirements

Allow only the required laboratory traffic:

| Source | Destination | Typical port | Purpose |
|---|---|---:|---|
| Windows Wazuh Agent | Wazuh Manager | `1514/TCP` | Agent event transport |
| Windows Wazuh Agent | Wazuh enrollment service | `1515/TCP` | Agent enrollment when enabled |
| ForenRAG host | Wazuh Indexer/OpenSearch | `9200/TCP` | Alert and archive queries |
| Wazuh Manager | ForenRAG host | `5000/TCP` | Optional alert webhook |
| ForenRAG process | Local Ollama | `11434/TCP` | Embedding and model requests |
| Windows victim | Approved external sources | `443/TCP` | S3 prerequisite downloads when explicitly permitted |

### 7. Verify the Telemetry Pipeline

Generate a benign process on the Windows VM:

```powershell
Start-Process cmd.exe -ArgumentList '/c whoami'
```

Then verify that:

1. Sysmon Event ID 1 appears in `Microsoft-Windows-Sysmon/Operational`.
2. The Wazuh Agent remains connected.
3. The event appears in `wazuh-archives-*` with the expected `agent.id`.
4. A matching laboratory rule produces a record in `wazuh-alerts-*` when applicable.
5. The JSON fields follow the paths expected by `app.py`, including `data.win.system.eventID` and `data.win.eventdata.processGuid`.

## Installation

### 1. Obtain the source

```bash
git clone https://github.com/viejopeter/ForenRAG.git
cd ForenRAG
```

### 2. Install Python dependencies

Install `uv` using its official instructions, then synchronize the locked environment:

```bash
uv sync --frozen
```

### 3. Install and prepare Ollama

Install Ollama using its official platform instructions, start its service, and pull the configured models:

```bash
ollama pull nomic-embed-text
ollama pull gemma4:e2b
ollama list
```

If `gemma4:e2b` is unavailable, select an installed local model and update `OLLAMA_MODEL`.

### 4. Configure ForenRAG

```bash
cp .env.example .env
```

Edit `.env` with environment-specific values. Never commit or publish this file.

```dotenv
OPENSEARCH_URL=https://<OPENSEARCH_HOST>:9200
OPENSEARCH_USER=<OPENSEARCH_USERNAME>
OPENSEARCH_PASSWORD=<STRONG_PASSWORD>
WAZUH_AGENT_ID=<WAZUH_AGENT_ID>
```

Use a least-privilege OpenSearch account with read access only to the required alert and archive indexes.

`.env.example` uses placeholders for credentials, hosts, and agent identifiers. Replace every placeholder before startup and keep the resulting `.env` private.

### 5. Build the knowledge index

```bash
uv run python build_chroma_db.py
```

This command embeds the sources under `knowledge_base/`, validates a staged `forenrag_kb` collection, and then replaces the local index in `chroma_db_storage/`. A failed build leaves the previous index available. Run it again after changing the corpus, embedding model, or chunk settings, and do not run it concurrently with the service.

### 6. Start the service

```bash
uv run python app.py
```

Verify that the local process is responding:

```bash
curl http://127.0.0.1:5000/status
```

The status endpoint confirms that Flask is running; it does not verify OpenSearch, ChromaDB, or Ollama health.

## Quick Validation

After completing the laboratory and application setup:

1. On the security VM, confirm that the Windows agent is connected and that `wazuh-alerts-*` and `wazuh-archives-*` are receiving events.
2. On the analysis host, start Ollama, build the Chroma index, and run `uv run python app.py`.
3. Confirm that `http://127.0.0.1:5000/status` responds and that the application console reports completion of the initial alert-ID seeding.
4. On the Windows victim, open an elevated PowerShell session and execute one Atomic Red Team scenario from the Evaluated Study section.
5. Wait for the settling window and report generation to complete, then inspect the new directory under `evidence_packages/` on the analysis host.
6. Run the corresponding Atomic cleanup invocation on the Windows victim and verify that its temporary or persistent changes were removed.

Successful execution produces `evidence.json` followed by `forensic_report.md`. Exact results depend on the deployment-specific Sysmon policy, Wazuh rules, retained telemetry, local models, and hardware.

## Configuration

All supported settings and defaults are documented in [`.env.example`](.env.example). The required connection values and optional OpenSearch controls are:

| Variable | Requirement | Purpose |
|---|---|---|
| `OPENSEARCH_URL` | Required | OpenSearch REST base URL |
| `OPENSEARCH_USER` | Required | HTTP Basic Authentication username |
| `OPENSEARCH_PASSWORD` | Required | HTTP Basic Authentication password |
| `OPENSEARCH_REQUEST_TIMEOUT_SECONDS` | Optional; default `30` | Maximum duration of an OpenSearch request |
| `OPENSEARCH_VERIFY_TLS` | Optional; default `false` | Enable certificate and hostname verification |
| `OPENSEARCH_CA_BUNDLE` | Optional; default empty | CA bundle used when TLS verification is enabled |
| `WAZUH_AGENT_ID` | Required | Windows endpoint identifier used for alert polling and archive correlation |

## Alert Input

ForenRAG uses built-in polling and also accepts optional webhook input:

- `POST /alert` accepts a Wazuh-style JSON alert.
- A daemon thread polls recent records from `wazuh-alerts-*` every three seconds.

A representative webhook body is:

```json
{
  "timestamp": "2026-01-01T00:00:00.000Z",
  "rule": {
    "id": "<RULE_ID>",
    "level": 12,
    "description": "<RULE_DESCRIPTION>",
    "mitre": {"id": ["TXXXX.XXX"]}
  },
  "data": {
    "win": {
      "eventdata": {
        "processGuid": "<PROCESS_GUID>",
        "parentProcessGuid": "<PARENT_PROCESS_GUID>",
        "commandLine": "<COMMAND_LINE>"
      }
    }
  }
}
```

Example submission:

```bash
curl -X POST http://127.0.0.1:5000/alert \
  -H 'Content-Type: application/json' \
  --data @alert.json
```

The endpoint currently has no authentication, signature validation, replay protection, schema validation, or rate limiting. Restrict it to an isolated laboratory network or place it behind authenticated ingress controls. Alert fields, telemetry, and knowledge passages are also untrusted LLM input and can introduce prompt-injection instructions into model-generated prose.

## Evidence Collection

After the settling window, `app.py` groups the session alerts, resolves available process ancestry and descendants, collects matching file and registry events, and records detector-provided and evidence-inferred ATT&CK labels. Queries use fixed result limits without pagination or an explicit incident time window, so each package is a bounded correlation result rather than a complete forensic acquisition.

## Retrieval

`forenrag_retriever.py` builds a query from the evidence package and retrieves technique-relevant passages from the local `forenrag_kb` collection. If the technique-filtered search has no usable result, it falls back to unrestricted vector search. Retrieved passages provide background knowledge; they are not incident evidence or confidence scores.

Standalone retrieval is available for inspection:

```bash
uv run python forenrag_retriever.py evidence_packages/<incident>/evidence.json
```

## Report Generation

`forenrag_reasoner.py` sends the structured evidence and retrieved background passages to the configured local Ollama model. It generates a six-section report covering the executive summary, timeline, evidence traceability, ATT&CK mapping, limitations, and response recommendations.

The current implementation renders the timeline and traceability sections deterministically from the evidence package and builds the ATT&CK table from evidence and retrieval metadata. Other sections remain model-generated and require analyst verification. The executable prompt is maintained in `forenrag_reasoner.py`.

Generate a report for an existing evidence package with:

```bash
uv run python forenrag_reasoner.py evidence_packages/<incident>/evidence.json
```

## Outputs

```text
evidence_packages/
└── NNN_incident_YYYYMMDD_HHMMSS_TECHNIQUE/
    ├── evidence.json
    └── forensic_report.md
```

`evidence.json` contains the correlated telemetry, technique metadata, retrieved passages, and internal processing metrics. `forensic_report.md` contains the generated six-section report. Internal metrics are not end-to-end alert-to-report latency.

## Evaluated Study

The completed controlled-laboratory study compared the automated ForenRAG workflow with a single-analyst reference review of the matched structured evidence package. Five Atomic Red Team scenarios were executed three times each, producing 15 matched trials:

| Scenario | ATT&CK technique | Atomic test | Intended activity |
|---|---|---:|---|
| S1 | `T1003.002` | 1 | Security Account Manager registry-hive dump |
| S2 | `T1059.001` | 17 | PowerShell command execution |
| S3 | `T1105` | 30 | Ingress tool transfer using `GUP.exe` |
| S4 | `T1053.005` | 1 | Scheduled-task persistence |
| S5 | `T1547.001` | 1 | Registry Run-key persistence |

### Windows Scenario Commands

The following commands were run from the Atomic Red Team PowerShell environment on the Windows victim VM. Each test execution was followed by its corresponding Atomic cleanup invocation.

#### S1: SAM Registry Dump

```powershell
Invoke-AtomicTest T1003.002 -TestNumbers 1
Invoke-AtomicTest T1003.002 -TestNumbers 1 -Cleanup
```

#### S2: PowerShell Command Execution

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 17
Invoke-AtomicTest T1059.001 -TestNumbers 17 -Cleanup
```

#### S3: Ingress Tool Transfer Using GUP.exe

```powershell
Invoke-AtomicTest T1105 -TestNumbers 30 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 30
Invoke-AtomicTest T1105 -TestNumbers 30 -Cleanup
```

#### S4: Scheduled Task Persistence

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

#### S5: Registry Run Key Persistence

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

### Laboratory Environment Used

The study trials were conducted with the following laboratory environment:

| Role | Platform and resources | Principal software |
|---|---|---|
| Analysis host | Windows 11 Home with WSL2; Intel Core i5-10300H, 32 GB RAM, GTX 1650 4 GB | Python 3.12, Ollama 0.30.11, ChromaDB 1.5.9, `gemma4:e2b`, `nomic-embed-text` |
| Victim endpoint VM | Windows 11 Enterprise Evaluation; 4 vCPU, 8192 MB RAM, 80 GB storage | Sysmon 15.21, Wazuh Agent 4.14.6, Atomic Red Team, PowerShell |
| Security services VM | Ubuntu 24.04.4; 4 vCPU, 6037 MB RAM, 60 GB storage | Wazuh Manager 4.14.6, OpenSearch 2.19.5 |

## Experiment Reproducibility

The reported experiments used the following local Ollama models:

| Model Name / Tag | Model ID | Exact SHA-256 Digest | Size | Role in ForenRAG |
|---|---|---|---|---|
| `gemma4:e2b` | `7fbdbf8f5e45` | `sha256:4e30e2665218745ef463f722c0bf86be0cab6ee676320f1cfadf91e989107448` | 7.2 GB | Reasoner / Forensic Report Generator |
| `nomic-embed-text:latest` | `0a109f422b47` | `sha256:970aa74c0a90ef7482477cf803618e776e173c007bf957f635f1015bfcfef0e6` | 274 MB | ChromaDB Embedding Model (768 dim) |

### ChromaDB Index Snapshot (`chroma_db_storage/`)

| Index parameter | Value |
|---|---|
| Collection Name | `forenrag_kb` |
| Collection UUID | `bc1c1ef9-4268-4143-b0d7-991e8e5eadab` |
| Total Chunks Indexed | 392 chunks |
| Vector Dimensions | 768 (L2 Distance / HNSW metric) |
| Text Splitter Settings | `chunk_size=1000`, `chunk_overlap=150` |

The generated index is not distributed; rebuild it from the tracked `knowledge_base/` sources with `uv run python build_chroma_db.py`. The index snapshot used for the experiments had SHA-256 `c5704942a28e416b1ccace01ba073e128eb906da86ef591c483de0875d6b4a76` for `chroma_db_storage/chroma.sqlite3`.

## Study Dataset

The [`study_dataset/`](study_dataset/) directory contains the sanitised trial-level data supporting the aggregate results reported in the ForenRAG manuscript. It includes timing, reference-review phase, collector-validation, retrieval, report-grounding, and major-error-category data together with definitions and calculation notes.

Raw OpenSearch exports, structured evidence packages, and complete investigation reports are not distributed because they contain security-sensitive laboratory telemetry and system identifiers.

## Known Limitations

Results depend on the endpoint telemetry policy, Wazuh rules, OpenSearch retention, knowledge corpus, models, model parameters, and hardware. The current prototype has these principal limitations:

- Evaluation is limited to a controlled laboratory and five Windows scenarios.
- Collection covers Sysmon Event IDs 1, 11, and 13 rather than a complete forensic acquisition.
- OpenSearch queries use fixed result limits without pagination or an explicit incident time window.
- Alert sessions and processed identifiers are held in memory without a durable processing queue.
- Webhook and polling ingestion can process the same alert more than once.
- Retrieval uses one primary analysis technique and may fall back to unrestricted vector search.
- Some report sections are model-generated and require analyst verification.
- There is no tracked automated test suite or CI workflow; end-to-end behavior requires laboratory validation.

## Security and Privacy

ForenRAG handles security-sensitive telemetry and executes adversary-emulation workflows. Use it only in an isolated, authorized laboratory with synthetic data, disposable systems, and reviewed cleanup procedures.

- `POST /alert` is unauthenticated, and the Flask development server binds to `0.0.0.0:5000`; restrict access to trusted laboratory systems.
- OpenSearch uses Basic Authentication, and the laboratory default disables certificate and hostname verification. Use least-privilege credentials and enable trusted TLS before any non-laboratory deployment.
- OpenSearch requests have a configurable timeout but no general retry or backoff policy; failed session finalization is retried up to three times.
- Evidence can contain identities, command lines, paths, hashes, registry data, and retrieved source text; protect it at rest and apply a retention policy.
- Generated files are not encrypted. Individual evidence and report files are replaced atomically, but the multi-file background pipeline is not transactional.
- Alert, telemetry, and corpus text can introduce prompt-injection content into model-generated report sections.

This is research software and is not ready for operational incident response without additional security and reliability controls.

## Knowledge Sources and Licensing

Original ForenRAG source code is licensed under the [Apache License 2.0](LICENSE). Copyright and attribution information is provided in [NOTICE](NOTICE).

The `knowledge_base/` directory includes third-party Atomic Red Team and LOLBAS material, MITRE ATT&CK descriptions, and project-authored incident-response notes informed by CISA and NIST guidance. Third-party material remains subject to its applicable terms and is not relicensed by the ForenRAG Apache license. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for provenance, licenses, and attribution.

The sanitised research data under `study_dataset/` are licensed separately under the [Creative Commons Attribution 4.0 International licence](study_dataset/LICENSE). The dataset licence does not apply to the ForenRAG software or third-party knowledge sources.

Generated ChromaDB files are excluded because they contain embedded representations of the source corpus.

## Troubleshooting

### No evidence package appears

- Confirm the alert level meets `MIN_RULE_LEVEL`.
- Confirm the event contains process GUID fields and the settling window has expired.
- Confirm raw Sysmon events exist in `wazuh-archives-*` and inspect the console for OpenSearch errors.

### Evidence exists but no report appears

- Confirm `chroma_db_storage/` has been built.
- Confirm Ollama is running with both configured models and inspect the console for pipeline errors.

### Retrieval returns irrelevant passages

- Verify source technique metadata and inspect the generated `rag_query` and `rag_passages`.
- Rebuild ChromaDB after changing the corpus, embedding model, or chunk settings.

## Citation

Archived ForenRAG releases are available through Zenodo at [https://doi.org/10.5281/zenodo.22088854](https://doi.org/10.5281/zenodo.22088854). Citation metadata is also provided in [`CITATION.cff`](CITATION.cff).

## Author

**Pedro Antonio Quinchanegua Sanchez**<br>
AI, Cybersecurity & Software Engineering Researcher<br>
[Website](https://pquinch.dev/)<br>
[LinkedIn](https://www.linkedin.com/in/pquinch/)
