# ForenRAG: Event-Driven Digital Forensic Investigation Framework

## 📌 Executive Summary

**ForenRAG** is an academic research framework designed to automate post-detection digital forensic evidence collection, context correlation, and report synthesis following cyber intrusion alerts. Modern Intrusion Detection Systems (IDS) and SIEM platforms flood Security Operations Centers (SOCs) with thousands of alerts daily, requiring human analysts to manually trace parent-child process trees, cross-reference registry/file modifications, and write incident reports—a process taking over 33 minutes per alert.

ForenRAG bridges threat detection and digital forensics by automatically capturing, correlating, and structuring forensic evidence immediately after a high-severity alert fires (Wazuh Rule Level $\ge 12$). Utilizing a local vector store (ChromaDB) and local LLM reasoning (Ollama `gemma4:e2b`), ForenRAG reduces post-detection triage latency from **33 minutes 08 seconds down to 12.35 seconds** (**99.38% operational time reduction**) with **zero unverified entity artifacts across evaluated benchmark trials**.

---

## 🖥️ System Architecture & Laboratory Topology

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
|                                                      |  ForenRAG Host (Code Analysis Engine)   |  |
|                                                      |  - Flask Alert Listener (app.py :5000)   |  |
|                                                      |  - OpenSearch Live Alerts Poller        |  |
|                                                      |  - Session Bucket Consolidation Engine  |  |
|                                                      |  - ChromaDB Vector Store (Phase 4)      |  |
|                                                      |  - Ollama Reasoning Engine (Phase 5)    |  |
|                                                      +-----------------------------------------+  |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

### Component Breakdown
1. **VM 1: Windows 11 Victim Client**:
   * **OS**: Windows 11 Enterprise (64-bit).
   * **Sysmon v15.0**:
     * `Event ID 1`: Process Creation (Process GUIDs, Parent GUIDs, CLI arguments, SHA256/IMPHASH).
     * `Event ID 11`: File Creation (`%TEMP%`, `AppData\Local\Temp`).
     * `Event ID 13`: Registry Modifications (`HKLM\...\Run`, `HKLM\...\TaskCache\Tree`).
   * **Wazuh Agent v4.7**: Streams Sysmon events to Wazuh Manager over Ports 1514/1515.

2. **VM 2: Ubuntu Security Server**:
   * **Wazuh Manager v4.7**: Ingests Sysmon logs, decodes telemetry, and tags alerts with rule levels (0–15).
   * **OpenSearch Indexer Engine (:9200)**:
     * `wazuh-alerts-*`: High-level intrusion alerts.
     * `wazuh-archives-*`: Raw Sysmon event logs required for process tree tracing.

3. **ForenRAG Analysis Host (Code Engine)**:
   * **Python Environment**: `uv` package manager with Python 3.10+.
   * **Ollama Server**: On-premise AI inference runner for embedding and reasoning models.
   * **ChromaDB**: On-premise vector database (`./chroma_db_storage`).

---

## 🤖 Required Local AI Models (Ollama)

ForenRAG runs **100% locally and on-premise**, guaranteeing data privacy and evidentiary security. Two specific Ollama models are required:

| Model Type | Model Name | Context Window / Dimension | Purpose | Pull Command |
| :--- | :--- | :--- | :--- | :--- |
| **Embedding Model** | `nomic-embed-text` | 768 Dimensions, 8,192 Context | Vector embedding of threat intelligence documents in ChromaDB | `ollama pull nomic-embed-text` |
| **Reasoning LLM** | `gemma4:e2b` | 7.2B Parameters ($T=0.1$) | Grounded 5-section DFIR report generation | `ollama pull gemma4:e2b` |

---

## 📈 Project Roadmap & Phase Status

- [x] **Phase 1: Lab Environment & Monitoring Infrastructure Setup**
  * Windows 11 Target VM + Ubuntu Security Server setup with Sysmon & Wazuh.
- [x] **Phase 2: Adversary Emulation & Manual Baseline Tracking**
  * Emulated attack scenarios (SAM Dump `T1003.002`, PowerShell `T1059.001`, Scheduled Task `T1053.005`) measuring manual SOC baseline ($33.1\text{ mins}$).
- [x] **Phase 3: Autonomous Event-Driven Evidence Collector**
  * Built `app.py` Flask listener and OpenSearch poller engine generating structured JSON evidence packages.
- [x] **Phase 4: Knowledge Retrieval Engine (RAG)**
  * On-premise vector store indexing threat intelligence and playbooks with ChromaDB and `nomic-embed-text`.
- [x] **Phase 5: Explainable LLM Reasoning & Incident Reporting**
  * Local Ollama reasoning pipeline generating 5-section DFIR reports (`forenrag_reasoner.py`).
- [x] **Phase 6: Framework Evaluation & Performance Benchmarking**
  * Evaluated across $N=9$ experimental trials, proving a **99.38% triage time reduction** ($12.35\text{s}$ vs $1,988\text{s}$).

---

## ⚙️ Step-by-Step Lab Replication Guide

Follow these exact steps to replicate the experimental laboratory and run ForenRAG on your system:

### Step 1: Install Dependencies & Setup Environment
1. **Install `uv`** (Rust-based Python package manager):
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
4. **Initialize Virtual Environment & Install Python Packages**:
   ```bash
   cd /home/codeinfra/projects/research/ForenRAG
   uv sync
   ```

---

### Step 2: Build the Vector Database Index (Phase 4)
Index the open-source threat intelligence documents from `./knowledge_base/` into ChromaDB:
```bash
uv run python build_chroma_db.py
```
*Expected Output*: `Indexed 496 text chunks into ChromaDB collection 'forenrag_kb'`.

---

### Step 3: Start the Autonomous ForenRAG Agent (Phases 3, 4 & 5)
Run the central agent script:
```bash
uv run python app.py
```
*The agent will:*
* Start a Flask REST server on `http://0.0.0.0:5000/alert` listening for real-time Wazuh webhooks.
* Asynchronously poll OpenSearch `wazuh-alerts-*` every 3 seconds for critical alerts ($\text{Rule Level} \ge 12$).
* Automatically trace 128-bit process trees, query ChromaDB, and invoke `gemma4:e2b` to save evidence JSON and markdown reports in `./evidence_packages/XXX_incident_.../`.

---

### Step 4: Execute Attack Scenarios on Windows 11 VM

While `app.py` is running, execute any of the 3 adversary emulation scenarios on your **Windows 11 VM**:

#### **Scenario A: SAM Registry Hive Dump (`T1003.002`)**
Open **Command Prompt as Administrator**:
```cmd
"C:\WINDOWS\system32\reg.exe" save HKEY_LOCAL_MACHINE\SAM C:\Windows\Temp\sam.bak
```

#### **Scenario B: Hidden PowerShell Execution (`T1059.001`)**
Open **PowerShell as Administrator**:
```powershell
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process calc.exe"
```

#### **Scenario C: Scheduled Task Persistence (`T1053.005`)**
Open **PowerShell as Administrator**:
```powershell
powershell -Command "schtasks /create /tn T1053_005_OnLogon /sc onlogon /tr 'cmd.exe /c calc.exe'; schtasks /delete /tn T1053_005_OnLogon /f"
```

---

### Step 5: Verify Generated Evidence & Reports

ForenRAG will automatically catch the alert, process the incident, and create a sequential output folder inside `evidence_packages/`:

```text
evidence_packages/
├── 001_incident_20260723_222415_T1105/
│   ├── evidence.json        # Standardized Sysmon JSON evidence package
│   └── forensic_report.md  # Grounded 5-section explainable DFIR report
```

