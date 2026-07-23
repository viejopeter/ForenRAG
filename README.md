# ForenRAG: Event-Driven Digital Forensic Investigation Framework

## 📌 Executive Summary

**ForenRAG** is an academic research framework designed to automate post-detection digital forensic evidence collection and correlation following cyber intrusion alerts. Modern Intrusion Detection Systems (IDS) and SIEM platforms flood Security Operations Centers (SOCs) with thousands of alerts, requiring analysts to manually trace parent-child process trees, cross-reference registry/file modifications, and write incident reports. 

ForenRAG bridges threat detection and digital forensics by automatically capturing, correlating, and structuring forensic evidence immediately after a high-severity alert fires, preparing standardized evidence packages for downstream Retrieval-Augmented Generation (RAG) and Large Language Model (LLM) reasoning.

---

## 🖥️ System Architecture & Lab Environment

The experimental research laboratory comprises three distinct system components:

```
+---------------------------------------------------------------------------------------------------+
|                                  LABORATORY INFRASTRUCTURE TOPOLOGY                               |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  +-------------------------------------+   Sysmon Telemetry  +---------------------------------+  |
|  |     VM 1: Windows 11 Victim Client  | ------------------->|  VM 2: Ubuntu Security Server   |  |
|  |  - Sysmon v15.0 (EID 1, 11, 13)       |    Port 1514/1515    |  - Wazuh Manager v4.7           |  |
|  |  - Wazuh Agent v4.7 (Agent ID: 002)   |                     |  - OpenSearch Indexer (:9200)   |  |
|  +-------------------------------------+                     +---------------------------------+  |
|                                                                              |                    |
|                                                                 Wazuh Alerts | (Level >= 12)      |
|                                                                              v                    |
|                                                      +-----------------------------------------+  |
|                                                      |  ForenRAG Machine (Code Host Engine)    |  |
|                                                      |  - Flask Alert Listener (app.py :5000)   |  |
|                                                      |  - OpenSearch Live Alerts Poller        |  |
|                                                      |  - Session Bucket Consolidation Engine  |  |
|                                                      |  - Evidence Package Builder (JSON)      |  |
|                                                      |  - ChromaDB RAG Engine (Phase 4)        |  |
|                                                      |  - Ollama Reasoning Engine (Phase 5)    |  |
|                                                      +-----------------------------------------+  |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### 1. VM 1: Windows 11 Victim Client
* **Operating System**: Windows 11 Enterprise (64-bit).
* **Endpoint Instrumentation**: 
  * **Sysmon v15.0**: Configured for enhanced security logging:
    * **Event ID 1 (Process Creation)**: Captures process GUIDs, parent GUIDs, full command lines, user SIDs, integrity levels, and cryptographic hashes (MD5, SHA256, IMPHASH).
    * **Event ID 11 (File Creation)**: Captures file drop events in sensitive temporary directories (`%TEMP%`, `AppData\Local\Temp`).
    * **Event ID 13 (Registry Value Set)**: Captures modifications to autorun keys, persistence mechanisms, and system settings.
  * **Wazuh Agent (v4.7)**: Streams Sysmon event channels in real-time to the Wazuh Manager.

### 2. VM 2: Ubuntu Security Server
* **Wazuh Manager (v4.7)**: Processes incoming endpoint event logs, decodes telemetry, and tags security alerts with severity levels (Levels 0–15) and MITRE ATT&CK technique IDs.
* **OpenSearch Indexer Engine**: Stores security events in two main indices:
  * `wazuh-alerts-*`: Stores high-level security alerts.
  * `wazuh-archives-*`: Stores raw Sysmon logs (EID 1, 11, 13) required for forensic process tree tracing.

### 3. ForenRAG Machine (Code Host & Analysis Engine)
* **Dedicated Host Machine**: Runs the core ForenRAG codebase.
* **Autonomous Telemetry Collector (`app.py`)**:
  * **Flask Webhook Listener**: Listens on `http://0.0.0.0:5000/alert` for real-time Wazuh webhooks.
  * **OpenSearch Live Poller**: Asynchronously polls `wazuh-alerts-*` every 3 seconds for critical alerts meeting the threshold ($\text{Rule Level} \ge 12$).
  * **5-Second Dynamic Settling Window**: Aggregates sequential attack actions into a single consolidated attack session bucket using `parentProcessGuid`.
  * **Process Lineage Tracing**: Recursively queries Sysmon EID 1 records from OpenSearch (`wazuh-archives-*`) up to depth 5 to construct full parent-child execution trees while filtering desktop shell noise (`explorer.exe`, `userinit.exe`).
  * **Artifact Fusion**: Fuses process execution trees with file drops (EID 11) and registry edits (EID 13).
  * **Sequential Subfolder Output**: Saves evidence packages into clean, indexed subfolders inside `./evidence_packages/XXX_incident_YYYYMMDD_HHMMSS_<MITRE_ID>/`.
* **Knowledge Retrieval Engine (RAG - Phase 4)**:
  * **Knowledge Base (`knowledge_base/`)**: Contains 9 official open-source threat intelligence documents from Red Canary Atomic Red Team and the LOLBAS project.
  * **ChromaDB Indexer (`build_chroma_db.py`)**: Chunks text and computes 768-dimensional vector embeddings via local Ollama `nomic-embed-text`, storing them in `./chroma_db_storage`.
  * **RAG Retriever (`forenrag_retriever.py`)**: Extracts telemetry parameters from Phase 3 JSON evidence packages and executes cosine similarity searches against ChromaDB.
* **Explainable AI Reasoning Engine (Phase 5)**:
  * **Reasoning Script (`forenrag_reasoner.py`)**: Combines structured Sysmon JSON evidence + ChromaDB retrieved RAG context, invoking local Ollama (`gemma4:e2b`) to generate a 5-section explainable DFIR investigation report (`forensic_report.md`).

---

## 📈 Current Project Progress & Roadmap

- [x] **Phase 1: Lab Environment & Monitoring Infrastructure Setup**
  * Windows 11 Victim VM + Ubuntu Security Server setup with Sysmon & Wazuh.
- [x] **Phase 2: Adversary Emulation & Manual Baseline Tracking**
  * Emulated attack scenarios (SAM Hive Dump `T1003.002`, Tool Transfer `T1105`, Scheduled Tasks `T1053.005`) and measured manual SOC analyst triage baseline (average $33.1\text{ mins}$).
- [x] **Phase 3: Autonomous Event-Driven Evidence Collector**
  * Built `app.py` Flask listener and OpenSearch poller engine generating structured JSON evidence packages.
- [x] **Phase 4: Knowledge Retrieval Engine (RAG)**
  * On-premise vector store indexing threat intelligence, LOLBAS binaries, and DFIR playbooks with ChromaDB and Ollama `nomic-embed-text`.
- [x] **Phase 5: Explainable LLM Reasoning & Incident Reporting**
  * Local Ollama reasoning pipeline generating explainable DFIR investigation reports (`forenrag_reasoner.py`).
- [ ] **Phase 6: Framework Evaluation & Performance Benchmarking** *(Upcoming)*
  * Live scenario evaluation comparing automated ForenRAG latency against manual SOC baseline.

---

## 🛠️ Environment Setup & Package Management using `uv`

This project uses **`uv`**, an extremely fast Python package and environment manager built in Rust.

### 1. Install `uv` (If not already installed)
On Linux / macOS:
```bash
curl -sSf https://astral.sh/uv/install.sh | sh
```

### 2. Initialize Virtual Environment & Install Dependencies
Navigate to the project root directory and run `uv sync` to create the `.venv` virtual environment and install the exact project dependencies specified in `pyproject.toml` / `requirements.txt`:
```bash
cd /home/codeinfra/projects/research/ForenRAG
uv sync
```

---

## 🚀 Execution & Usage Guide

### 1. Run the Complete Automated Pipeline Agent (Phases 3, 4 & 5)
Start the autonomous alert listener and OpenSearch poller agent. Whenever a High/Critical alert fires (Rule Level $\ge 12$), it automatically collects telemetry, queries ChromaDB, and generates an explainable DFIR report in seconds:
```bash
uv run python app.py
```

### 2. Build / Update the ChromaDB Vector Store (Phase 4)
Index the knowledge base documents from `./knowledge_base/` into ChromaDB:
```bash
uv run python build_chroma_db.py
```

### 3. Run RAG Knowledge Retrieval Standalone (Phase 4)
Query ChromaDB using an evidence JSON package:
```bash
uv run python forenrag_retriever.py
```

### 4. Run Explainable LLM Report Generation Standalone (Phase 5)
Generate a forensic report for an existing evidence package using local Ollama `gemma4:e2b`:
```bash
uv run python forenrag_reasoner.py
```
