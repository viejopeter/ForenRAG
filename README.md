# ForenRAG: An Event-Driven Retrieval-Augmented Framework for Explainable Digital Forensic Investigation after Cyber Intrusion Detection

## 📌 Executive Summary

**ForenRAG** is an academic research framework designed to automate post-detection digital forensic evidence collection, context correlation, and report synthesis following cyber intrusion alerts. Modern Intrusion Detection Systems (IDS) and SIEM platforms generate a high volume of alerts daily, requiring security analysts to manually trace parent-child process trees, cross-reference registry/file modifications, and write incident reports.

ForenRAG bridges threat detection and digital forensics by capturing, correlating, and structuring forensic evidence after a high-severity alert fires (configurable via `MIN_RULE_LEVEL`). Utilizing a local Retrieval-Augmented Generation (RAG) architecture powered by ChromaDB vector storage and local LLM reasoning (Ollama `gemma4:e2b`), ForenRAG performs automated telemetry extraction, root ancestor process tree correlation, and explainable DFIR report generation.

---

## 🧠 Retrieval-Augmented Generation (RAG) Architecture

In digital forensic investigations, raw endpoint telemetry provides the *empirical evidence*, but Large Language Models (LLMs) require grounded domain expertise to analyze complex attacks without hallucinating. ForenRAG implements a dedicated two-stage RAG architecture:

1. **Vector Knowledge Indexing**: Official threat intelligence documents, MITRE ATT&CK playbooks, CISA containment guides, and LOLBAS definitions located in `./knowledge_base/` are chunked and embedded into 768-dimensional vectors using `nomic-embed-text`, persisting in a local **ChromaDB** vector database (`./chroma_db_storage/`).
2. **Context-Grounded DFIR Synthesis**: When an intrusion alert fires, `forenrag_retriever.py` formulates a query based on the triggered rule description, MITRE technique IDs, and process image names. It retrieves the top-K most relevant threat intelligence passages (`RAG_TOP_K`), which `forenrag_reasoner.py` injects alongside the raw Sysmon telemetry graph into **`gemma4:e2b`**. This guarantees strictly grounded, explainable DFIR reports.

---

## 🛠️ Technology Stack & Purpose

| Technology | Role / Category | Purpose in ForenRAG |
| :--- | :--- | :--- |
| **Python 3.10+** | Programming Language | Core backend language orchestrating all telemetry, correlation, and AI modules. |
| **Flask** | Web Framework | Hosts real-time HTTP POST webhook listener (`POST /alert` on `:5000`) in `app.py`. |
| **LangChain** | AI Orchestration | Integrates prompt templates, ChromaDB vector retriever, and Ollama LLM execution pipelines. |
| **Ollama** | Local AI Engine | Executes local LLM reasoning and embedding models on-premise without external cloud APIs. |
| **gemma4:e2b** | Reasoning LLM (`OLLAMA_MODEL`) | Analyzes evidence packages and synthesizes structured 5-section DFIR reports. |
| **Nomic-Embed-Text** | Embedding Model (`EMBEDDING_MODEL`) | Converts threat intelligence and playbooks into 768-dimensional vector embeddings. |
| **ChromaDB** | Vector Database | Stores knowledge embeddings in `./chroma_db_storage/` and performs top-K similarity search. |
| **OpenSearch** | Telemetry Search Engine | Indexes raw Sysmon events (`wazuh-archives-*`) and alerts (`wazuh-alerts-*`) for process graph tracing. |
| **Sysmon & Wazuh** | Endpoint SIEM Telemetry | Captures process lineage (EID 1), files (EID 11), registry keys (EID 13), and evaluates alert levels. |
| **`uv`** | Package Manager | Fast Rust-based Python dependency management and environment execution (`uv run`). |
| **Atomic Red Team** | Adversary Emulation | Executes standardized MITRE ATT&CK attack scenarios (`Invoke-AtomicTest`) on victim VM. |

---

## 📁 Repository Directory Structure

```text
ForenRAG/
├── .env.example              # Master environment configuration template
├── .env                      # Active environment variables (Git-ignored)
├── .gitignore                # Excludes virtualenv, .env, and local artifacts
├── app.py                    # Flask webhook listener, OpenSearch poller & session engine
├── build_chroma_db.py        # ChromaDB vector store indexer
├── forenrag_retriever.py     # RAG knowledge similarity search engine
├── forenrag_reasoner.py      # Ollama LLM DFIR report reasoning engine
├── pyproject.toml            # Python project dependencies (managed via uv)
├── requirements.txt          # Pip requirements file
├── knowledge_base/           # Open-source threat intelligence & playbooks (.md, .yml)
├── chroma_db_storage/        # Persistent ChromaDB vector store (Generated)
└── evidence_packages/        # Output directory for structured DFIR packages (Generated)
    └── XXX_incident_TIMESTAMP_MITRE/
        ├── evidence.json     # Structured Sysmon telemetry JSON package
        └── forensic_report.md# Grounded 5-section explainable DFIR report
```

---

## 🏛️ Module Architecture & Core Functions

### 1. Telemetry Collector & Session Engine (`app.py`)
* **Dual Ingestion Channels**:
  * **Webhook Channel (`POST /alert`)**: Receives real-time HTTP POST alerts from Wazuh Manager.
  * **OpenSearch Poller Thread**: Asynchronously queries `wazuh-alerts-*` every 3 seconds for critical alerts ($\text{Rule Level} \ge \text{MIN\_RULE\_LEVEL}$).
* **Root Ancestor Process Tree Correlation (`get_root_ancestor_guid`)**: Dynamically queries Sysmon Event ID 1 (Process Creation) logs in `wazuh-archives-*` to trace parent process GUIDs up to root user shells (`explorer.exe`, `userinit.exe`, `services.exe`). This guarantees that multi-stage process executions (`powershell` $\rightarrow$ `cmd` $\rightarrow$ `schtasks`) consolidate into a single incident session.
* **Process Lineage Tracer (`trace_process_tree`)**: Recursively extracts process execution nodes up to a maximum depth of 5, capturing process IDs, image paths, CLI arguments, user SIDs, integrity levels, and file hashes (MD5/SHA256/IMPHASH).
* **Artifact Correlation Engine (`collect_artifacts`)**: Queries OpenSearch for Sysmon Event ID 11 (File Creations in `%TEMP%` / `AppData`) and Event ID 13 (Registry Modifications under `Run` keys).
* **Session Consolidation (`finalize_session`)**: Consolidates alerts within a configurable settling window (`SETTLING_WINDOW_SECONDS`), calculates collection latency ($L_{\text{coll}}$), writes `evidence.json`, and triggers the reasoning pipeline.

### 2. Knowledge Base Indexer (`build_chroma_db.py`)
* Reads threat intelligence documents and playbooks from `./knowledge_base/` (`.md`, `.yml`, `.yaml`).
* Extracts and attaches standardized MITRE technique metadata tags (`metadata={"source": ..., "technique": "TXXXX.XXX"}`) for target technique isolation.
* Splits documents into structured 1,000-character text chunks using LangChain `RecursiveCharacterTextSplitter` (`CHROMA_CHUNK_SIZE=1000`, `CHROMA_CHUNK_OVERLAP=150`) to preserve section headings alongside attack commands.
* Computes vector embeddings via local Ollama embedding models (`EMBEDDING_MODEL`) and persists the vector store in `./chroma_db_storage/`.

### 3. RAG Retrieval Engine (`forenrag_retriever.py`)
* Formulates targeted search queries by extracting rule descriptions, MITRE technique IDs, and primary attack binaries while filtering out generic background binaries (`hostname.exe`, `whoami.exe`, `cmd.exe`).
* Implements a two-stage hybrid retrieval pipeline:
  * **Stage 1 (Metadata Filter)**: Queries ChromaDB with a `filter={"technique": primary_mitre}` constraint to retrieve exact technique playbooks.
  * **Stage 2 (Similarity Search Fallback)**: Falls back to unguided dense vector similarity search if metadata filtering yields fewer than `top_k` passages.
* Returns top-K threat passages (`RAG_TOP_K`) alongside query metadata for context-grounded reasoning.

### 4. LLM Reasoning Engine (`forenrag_reasoner.py`)
* Formats raw Sysmon telemetry and retrieved RAG context into a grounded prompt template.
* Invokes local Ollama LLMs (`OLLAMA_MODEL`) at low temperature (`LLM_TEMPERATURE`) and context window (`LLM_NUM_CTX`).
* Synthesizes a 5-section explainable DFIR report covering Executive Summary, Process Lineage Table, Evidence Traceability, MITRE/LOLBAS Mapping, and Remediation Playbooks.
* Computes reasoning latency ($L_{\text{reason}}$) and total latency ($T_{\text{automated}} = L_{\text{coll}} + L_{\text{reason}}$), appending metrics to `forensic_report.md`.

---

## 🖥️ System Architecture Topology

```
+---------------------------------------------------------------------------------------------------+
|                                  LABORATORY INFRASTRUCTURE TOPOLOGY                               |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  +-------------------------------------+   Sysmon Telemetry  +---------------------------------+  |
|  |     VM 1: Windows 11 Victim Client  | ------------------->|  VM 2: Ubuntu Security Server   |  |
|  |  - Sysmon v15.0 (EID 1, 11, 13)       |    TLS Port 1514    |  - Wazuh Manager v4.7           |  |
|  |  - Atomic Red Team Test Suite       |                     |  - OpenSearch Indexer (:9200)   |  |
|  |  - Wazuh Agent (WAZUH_AGENT_ID)     |                     +---------------------------------+  |
|  +-------------------------------------+                                    |              |      |
|                                                                    Wazuh    |              | REST |
|                                                                   Webhook   |              | API  |
|                                                                (POST /alert)|              | (:9200)
|                                                              (Level >= 12)  v              v      |
|                                                      +-----------------------------------------+  |
|                                                      |  ForenRAG Host (Analysis Engine)        |  |
|                                                      |  - Flask Alert Listener (app.py :5000)   |  |
|                                                      |  - OpenSearch Live Alerts & Graph Poller|  |
|                                                      |  - Root Ancestor Process Tree Engine    |  |
|                                                      |  - ChromaDB Vector Store Engine         |  |
|                                                      |  - Local Ollama Engine (OLLAMA_MODEL)   |  |
|                                                      +-----------------------------------------+  |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

---

## ⚙️ Environment Configuration Reference (`.env`)

All parameters are configured via environment variables in `.env`:

| Parameter | Type | Default Value | Description |
| :--- | :---: | :--- | :--- |
| `OPENSEARCH_URL` | String | `https://<OPENSEARCH_IP>:9200` | OpenSearch Indexer REST API URL |
| `OPENSEARCH_USER` | String | `admin` | OpenSearch HTTP Basic Auth Username |
| `OPENSEARCH_PASSWORD` | String | `admin` | OpenSearch HTTP Basic Auth Password |
| `WAZUH_AGENT_ID` | String | `002` | Wazuh Agent ID of target Windows node |
| `MIN_RULE_LEVEL` | Integer | `12` | Minimum Wazuh rule severity level to trigger collection |
| `SETTLING_WINDOW_SECONDS` | Float | `15.0` | Session consolidation settling window in seconds |
| `OLLAMA_BASE_URL` | String | `http://localhost:11434` | Ollama local REST API base endpoint |
| `OLLAMA_MODEL` | String | `gemma4:e2b` | Ollama reasoning LLM model tag |
| `EMBEDDING_MODEL` | String | `nomic-embed-text` | Ollama embedding model tag for ChromaDB |
| `LLM_TEMPERATURE` | Float | `0.1` | Temperature setting for LLM inference |
| `LLM_NUM_CTX` | Integer | `8192` | LLM context window size (tokens) |
| `RAG_TOP_K` | Integer | `3` | Number of top knowledge passages retrieved per query |
| `CHROMA_CHUNK_SIZE` | Integer | `400` | Character chunk size for text splitting |
| `CHROMA_CHUNK_OVERLAP` | Integer | `50` | Character overlap size for text splitting |

---

## ⚙️ Step-by-Step Execution Guide

### Step 1: Install Dependencies & Setup Environment

1. **Install `uv`** (Python package manager):
   ```bash
   curl -sSf https://astral.sh/uv/install.sh | sh
   ```
2. **Install Ollama**:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```
3. **Pull Required AI Models**:
   ```bash
   ollama pull nomic-embed-text
   ollama pull gemma4:e2b
   ```
4. **Initialize Virtual Environment & Install Dependencies**:
   ```bash
   uv sync
   ```
5. **Configure Environment Variables (`.env`)**:
   Copy `.env.example` to `.env` and fill in your OpenSearch server IP and credentials:
   ```bash
   cp .env.example .env
   ```

---

### Step 2: Build Vector Database Index (`build_chroma_db.py`)

Index threat intelligence documents from `./knowledge_base/` into ChromaDB:

```bash
uv run python build_chroma_db.py
```

---

### Step 3: Launch Autonomous Agent (`app.py`)

Start the central telemetry collector and automated reasoning engine:

```bash
uv run python app.py
```

---

### Step 4: Execute Adversary Emulation Suite (Atomic Red Team)

While `app.py` is running, execute any of the **5 Benchmark Attack Scenarios** using Atomic Red Team on your **Windows 11 Victim Client**:

#### 1️⃣ Scenario 1: SAM Registry Dump (`T1003.002` - Test #1)
```powershell
Invoke-AtomicTest T1003.002 -TestNumbers 1
Invoke-AtomicTest T1003.002 -TestNumbers 1 -Cleanup
```

#### 2️⃣ Scenario 2: PowerShell Command Execution (`T1059.001` - Test #17)
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 17
Invoke-AtomicTest T1059.001 -TestNumbers 17 -Cleanup
```

#### 3️⃣ Scenario 3: Ingress Tool Transfer via GUP.exe (`T1105` - Test #30)
```powershell
Invoke-AtomicTest T1105 -TestNumbers 30 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 30
Invoke-AtomicTest T1105 -TestNumbers 30 -Cleanup
```

#### 4️⃣ Scenario 4: Scheduled Task Persistence (`T1053.005` - Test #1)
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

#### 5️⃣ Scenario 5: Registry Run Key Persistence (`T1547.001` - Test #1)
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

---

### Step 5: Output Verification

ForenRAG automatically detects the intrusion alert, extracts the evidence graph, queries ChromaDB, and generates an output package inside `evidence_packages/`:

```text
evidence_packages/
└── 001_incident_20260802_065744_T1053.005/
    ├── evidence.json        # Standardized Sysmon JSON telemetry package
    └── forensic_report.md  # Grounded 5-section explainable DFIR report
```
