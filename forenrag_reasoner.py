"""
ForenRAG Phase 5: Explainable AI Investigation Reasoning Engine
---------------------------------------------------------------
Integrates Phase 3 Evidence Package + Phase 4 RAG Retrieved Knowledge
and feeds it into local Ollama via LangChain to generate an explainable DFIR report.
"""

import os
import json
import sys
import time
import html
import ntpath
import re
from datetime import datetime, timezone
from dotenv import load_dotenv
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from forenrag_retriever import retrieve_rag_context

load_dotenv()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma4:e2b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_NUM_CTX = int(os.getenv("LLM_NUM_CTX", "16384"))
LLM_NUM_PREDICT = int(os.getenv("LLM_NUM_PREDICT", "6144"))
TIMELINE_PLACEHOLDER = "[[DETERMINISTIC_TIMELINE]]"
TRACEABILITY_PLACEHOLDER = "[[DETERMINISTIC_EVIDENCE_TRACEABILITY]]"

def _parse_timestamp(value):
    """Parse evidence timestamps for deterministic chronological sorting."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def _markdown_cell(value):
    """Render untrusted evidence text safely inside a Markdown table cell."""
    text = html.unescape(str(value or ""))
    return text.replace("|", "\\|").replace("`", "\\`").replace("\r", " ").replace("\n", " ")

def build_timeline_table(pkg):
    """Build an exact chronological process timeline without LLM transformation."""
    processes = sorted(
        pkg.get("process_tree", []),
        key=lambda proc: _parse_timestamp(proc.get("timestamp", "9999-12-31T23:59:59+00:00")),
    )
    if not processes:
        return "No process creation events were collected."

    processes_by_guid = {
        proc.get("process_guid"): proc
        for proc in processes
        if proc.get("process_guid")
    }
    lines = [
        "| Timestamp (UTC) | PID | Process | Process GUID | Parent Process | Parent GUID | User | Integrity | Command Line |",
        "|---|---:|---|---|---|---|---|---|---|",
    ]
    for proc in processes:
        parent_guid = proc.get("parent_process_guid")
        parent = processes_by_guid.get(parent_guid, {})
        parent_image = parent.get("image")
        parent_name = ntpath.basename(parent_image) if parent_image else "Not present in evidence"
        lines.append(
            f"| {_markdown_cell(proc.get('timestamp'))} "
            f"| {_markdown_cell(proc.get('process_id'))} "
            f"| `{_markdown_cell(ntpath.basename(proc.get('image', '')) or 'Unknown')}` "
            f"| `{_markdown_cell(proc.get('process_guid'))}` "
            f"| `{_markdown_cell(parent_name)}` "
            f"| `{_markdown_cell(parent_guid)}` "
            f"| `{_markdown_cell(proc.get('user'))}` "
            f"| {_markdown_cell(proc.get('integrity_level'))} "
            f"| `{_markdown_cell(proc.get('command_line'))}` |"
        )

    start = processes[0].get("timestamp")
    end = processes[-1].get("timestamp")
    lines.extend([
        "",
        f"**Observed process activity window:** {_markdown_cell(start)} to {_markdown_cell(end)}.",
    ])
    return "\n".join(lines)

def build_evidence_traceability(pkg):
    """Render observed artifacts exactly and keep command outcomes unconfirmed."""
    processes = pkg.get("process_tree", [])
    artifacts = pkg.get("artifacts", {})
    file_creations = artifacts.get("file_creations", [])
    registry_sets = artifacts.get("registry_sets", [])

    reg_commands = [
        proc for proc in processes
        if ntpath.basename(proc.get("image", "")).lower() == "reg.exe"
    ]
    cleanup_commands = [
        proc for proc in processes
        if ntpath.basename(proc.get("image", "")).lower() == "cmd.exe"
        and " del " in f" {html.unescape(proc.get('command_line') or '').lower()} "
    ]

    lines = [
        "#### Process and Command Evidence",
        "Section 2 contains the authoritative process identifiers, lineage, and timestamps.",
    ]
    if reg_commands:
        lines.append(
            f"- {len(reg_commands)} observed `reg.exe` process creation event(s) contained registry-save commands. "
            "These events confirm that the commands were launched; they do not independently confirm command success or output-file creation."
        )
    else:
        lines.append("- No `reg.exe` process creation events were collected.")
    if cleanup_commands:
        lines.append(
            f"- {len(cleanup_commands)} observed `cmd.exe` process creation event(s) contained file-deletion commands. "
            "These events confirm deletion attempts; successful deletion was not observed."
        )

    lines.extend(["", "#### Observed File Creation Events"])
    if file_creations:
        lines.extend([
            "| Timestamp (UTC) | Process | Process GUID | Target Filename |",
            "|---|---|---|---|",
        ])
        for artifact in sorted(file_creations, key=lambda item: _parse_timestamp(item["timestamp"])):
            lines.append(
                f"| {_markdown_cell(artifact.get('timestamp'))} "
                f"| `{_markdown_cell(ntpath.basename(artifact.get('image', '')) or 'Unknown')}` "
                f"| `{_markdown_cell(artifact.get('process_guid'))}` "
                f"| `{_markdown_cell(artifact.get('target_filename'))}` |"
            )
    else:
        lines.append("No file creation events were collected for the correlated processes.")
    lines.append(
        "No observed file creation event in this evidence package independently confirms creation of a SAM, SYSTEM, or SECURITY hive output file unless such a path is explicitly listed above."
    )

    lines.extend(["", "#### Observed Registry Set Events"])
    if registry_sets:
        lines.extend([
            "| Timestamp (UTC) | Process | Process GUID | Target Object | Details |",
            "|---|---|---|---|---|",
        ])
        for artifact in sorted(registry_sets, key=lambda item: _parse_timestamp(item["timestamp"])):
            lines.append(
                f"| {_markdown_cell(artifact.get('timestamp'))} "
                f"| `{_markdown_cell(ntpath.basename(artifact.get('image', '')) or 'Unknown')}` "
                f"| `{_markdown_cell(artifact.get('process_guid'))}` "
                f"| `{_markdown_cell(artifact.get('target_object'))}` "
                f"| {_markdown_cell(artifact.get('details'))} |"
            )
        lines.append(
            "These registry events are reported for completeness. Their presence does not establish a relationship to the triggering activity without additional evidence."
        )
    else:
        lines.append("No registry set events were collected for the correlated processes.")

    return "\n".join(lines)

def inject_timeline(report, timeline):
    """Replace the model placeholder, or its Section 2 body, with the exact timeline."""
    if TIMELINE_PLACEHOLDER in report:
        return report.replace(TIMELINE_PLACEHOLDER, timeline)

    section_pattern = re.compile(
        r"(^#{1,6}\s+2\..*?$).*?(?=^#{1,6}\s+3\.)",
        flags=re.MULTILINE | re.DOTALL,
    )
    if not section_pattern.search(report):
        raise ValueError("Generated report omitted the required Section 2 timeline location")
    return section_pattern.sub(
        lambda match: f"{match.group(1)}\n\n{timeline}\n\n",
        report,
        count=1,
    )

def inject_traceability(report, traceability):
    """Replace the model's Section 3 body with deterministic evidence traceability."""
    if TRACEABILITY_PLACEHOLDER in report:
        return report.replace(TRACEABILITY_PLACEHOLDER, traceability)

    section_pattern = re.compile(
        r"(^#{1,6}\s+3\..*?$).*?(?=^#{1,6}\s+4\.)",
        flags=re.MULTILINE | re.DOTALL,
    )
    if not section_pattern.search(report):
        raise ValueError("Generated report omitted the required Section 3 traceability location")
    return section_pattern.sub(
        lambda match: f"{match.group(1)}\n\n{traceability}\n\n",
        report,
        count=1,
    )

def format_evidence_summary(pkg):
    """Formats raw Sysmon JSON payload into structured text blocks for strictly grounded telemetry LLM reasoning."""
    alert = pkg.get("trigger_alert", {})
    tree = pkg.get("process_tree", [])
    artifacts = pkg.get("artifacts", {})
    detector_techniques = pkg.get("detector_techniques", alert.get("mitre_id", []))
    analysis_techniques = pkg.get("analysis_techniques", detector_techniques)
    
    summary_lines = [
        f"- Trigger Rule: {alert.get('rule_description')} (Rule Level {alert.get('rule_level')})",
        f"- Trigger Rule ID: {alert.get('rule_id')}",
        f"- Detector MITRE Technique IDs: {', '.join(detector_techniques)}",
        f"- Evidence-derived Analysis Technique IDs: {', '.join(analysis_techniques)}",
        f"- Trigger Timestamp: {alert.get('timestamp')}",
        f"- Trigger Process GUID: {alert.get('process_guid')}",
        f"- Trigger Parent Process GUID: {alert.get('parent_guid')}",
        f"- Trigger Command Line: {alert.get('command_line')}",
        "\n--- Process Execution Lineage ---"
    ]
    
    for proc in tree:
        summary_lines.append(
            f"  * Event Type: Observed Process Creation\n"
            f"    Timestamp: {proc.get('timestamp')}\n"
            f"    Process GUID: {proc.get('process_guid')}\n"
            f"    Parent Process GUID: {proc.get('parent_process_guid')}\n"
            f"    PID: {proc.get('process_id')} | Image: {proc.get('image')} | User: {proc.get('user')} | Integrity: {proc.get('integrity_level')}\n"
            f"    CmdLine: {proc.get('command_line')}"
        )
        
    summary_lines.append("\n--- File Creation Artifacts ---")
    file_creations = artifacts.get("file_creations", [])
    if file_creations:
        for f in file_creations:
            summary_lines.append(
                f"  * Event Type: Observed File Creation\n"
                f"    Timestamp: {f.get('timestamp')}\n"
                f"    Process GUID: {f.get('process_guid')}\n"
                f"    Image: {f.get('image')}\n"
                f"    Target Filename: {f.get('target_filename')}"
            )
    else:
        summary_lines.append("  * No file creation events were collected for the correlated processes.")
        
    summary_lines.append("\n--- Registry Set Artifacts ---")
    registry_sets = artifacts.get("registry_sets", [])
    if registry_sets:
        for r in registry_sets:
            summary_lines.append(
                f"  * Event Type: Observed Registry Set\n"
                f"    Timestamp: {r.get('timestamp')}\n"
                f"    Process GUID: {r.get('process_guid')}\n"
                f"    Image: {r.get('image')}\n"
                f"    Target Object: {r.get('target_object')} | Details: {r.get('details')}"
            )
    else:
        summary_lines.append("  * No registry set events were collected for the correlated processes.")

    summary_lines.extend([
        "\n--- Collection Coverage and Limitations ---",
        "  * Process creation telemetry: Collected (Sysmon Event ID 1).",
        "  * File creation telemetry: Collected where present (Sysmon Event ID 11).",
        "  * Registry set telemetry: Collected where present (Sysmon Event ID 13).",
        "  * File deletion telemetry: Not collected; deletion success cannot be confirmed.",
        "  * Network telemetry: Not collected; command-and-control, lateral movement, and exfiltration cannot be assessed.",
        "  * Process exit codes: Not collected; command success cannot be confirmed from process creation alone.",
    ])
        
    return "\n".join(summary_lines)

def generate_forensic_report(evidence_json_path, model_name=None):
    """
    Ingests Phase 3 JSON evidence + Phase 4 RAG retrieved context,
    invokes local Ollama LLM, and generates an explainable DFIR report.
    """
    model_name = model_name or OLLAMA_MODEL
    if not os.path.exists(evidence_json_path):
        raise FileNotFoundError(f"Evidence JSON file not found: {evidence_json_path}")

    start_t = time.time()
    print(f"\n==================================================")
    print(f"   ForenRAG Phase 5 Investigation Reasoning Engine")
    print(f"   Target Evidence Package: {evidence_json_path}")
    print(f"   Ollama Local LLM Model: {model_name}")
    print(f"==================================================\n")

    # Step 1: Retrieve RAG Knowledge Context from ChromaDB (Phase 4)
    retrieved_passages, query_str = retrieve_rag_context(evidence_json_path)
    kb_context = "\n\n".join([f"--- Knowledge Chunk ({p['source']}) ---\n{p['content']}" for p in retrieved_passages])

    # Step 2: Read Evidence Package JSON & Format Text Summary
    with open(evidence_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    evidence_text = format_evidence_summary(pkg)

    # Step 3: Define Explainable DFIR Grounding Prompt Template
    prompt_template = """You are ForenRAG, an expert Digital Forensics and Incident Response (DFIR) analyst.
Analyze the endpoint evidence and use the retrieved knowledge only to explain observed behavior and recommend response actions. Generate a professional, precise, and evidence-grounded report.

ANALYSIS DATE (UTC):
{analysis_date}

COLLECTED EVIDENCE SUMMARY:
{evidence_text}

RETRIEVED BACKGROUND KNOWLEDGE (NOT INCIDENT EVIDENCE):
{rag_context}

MANDATORY GROUNDING RULES:
1. Treat only the COLLECTED EVIDENCE SUMMARY as incident evidence. RAG context is general background and must never be presented as an observed incident fact.
2. Preserve the exact supplied timestamps, PIDs, process GUIDs, parent process GUIDs, command lines, users, and integrity levels. Sort the timeline chronologically. Never invent timestamps or relative times.
3. Reconstruct lineage only from matching Process GUID and Parent Process GUID values. Do not imply ancestry that the evidence does not establish.
4. Process creation proves that a command was launched, not that it succeeded. State "attempted" when no exit status or corroborating result exists.
5. A command line containing an output path does not prove that the output file was created. Claim observed file creation only for entries explicitly listed as Observed File Creation events.
6. A deletion command proves a deletion attempt, not successful deletion. File deletion telemetry is unavailable.
7. Do not claim exfiltration, command-and-control, or lateral movement without network or transfer evidence. State that these outcomes cannot be assessed when appropriate.
8. Do not label a file as a payload, malware, dropper, executable script, IOC, or obfuscated content without supporting execution, content, detection, or reputation evidence.
9. A filename matching __PSScriptPolicyTest_*.ps1 is consistent with a PowerShell execution-policy test. Do not classify it as malicious solely because it is a script in a temporary directory.
10. Do not describe registry activity as persistence, staging, or attacker activity unless the target and behavior directly support that conclusion. Explorer NotifyIconSettings publisher updates are not evidence of persistence by themselves.
11. Map only ATT&CK techniques directly supported by collected evidence. Use the correct ATT&CK tactic names and IDs. Do not add a technique based only on a tool being present.
12. Distinguish clearly between Observed facts, Inferences, Background context, and Unknown or unconfirmed outcomes. Use calibrated language and explicitly identify uncertainty.
13. Do not call a user unauthorized or an activity adversary-controlled unless identity or authorization evidence supports that conclusion. You may classify behavior as suspicious or consistent with a technique.
14. Do not claim credentials were obtained or compromised merely because registry-save commands were launched.
15. Include all relevant observed artifacts, including apparently benign or unrelated artifacts, but accurately explain whether a relationship to the alert is established.

Provide a structured report with these sections:
1. Executive Summary & Severity Rating
2. Chronological Timeline & Process Lineage Analysis. Under this heading, output only the exact placeholder [[DETERMINISTIC_TIMELINE]]. Do not construct, summarize, or reproduce the timeline yourself.
3. Evidence Traceability. Under this heading, output only the exact placeholder [[DETERMINISTIC_EVIDENCE_TRACEABILITY]]. Do not reproduce process identifiers, timestamps, lineage, commands, file events, or registry events yourself.
4. MITRE ATT&CK Mapping & LOLBAS Identification
5. Evidence Limitations & Unconfirmed Outcomes
6. Recommended Response & Remediation Playbook

Use the supplied analysis date rather than a placeholder. Do not output "[Current Date]". Do not include claims that violate the grounding rules.

FORENSIC REPORT:"""

    prompt = PromptTemplate(
        input_variables=["analysis_date", "evidence_text", "rag_context"],
        template=prompt_template
    )

    print(f"\n[+] Invoking Ollama LLM Model '{model_name}' via LangChain...")
    llm = OllamaLLM(
        model=model_name,
        base_url=OLLAMA_BASE_URL,
        temperature=LLM_TEMPERATURE,
        num_ctx=LLM_NUM_CTX,
        num_predict=LLM_NUM_PREDICT,
    )

    formatted_prompt = prompt.format(
        analysis_date=datetime.now(timezone.utc).date().isoformat(),
        evidence_text=evidence_text,
        rag_context=kb_context
    )

    response = llm.invoke(formatted_prompt)
    response = inject_timeline(response, build_timeline_table(pkg))
    response = inject_traceability(response, build_evidence_traceability(pkg))

    print("\n==================================================")
    print("   GENERATED EXPLAINABLE FORENSIC INVESTIGATION REPORT")
    print("==================================================\n")
    print(response)

    reasoning_latency = round(time.time() - start_t, 3)
    coll_latency = pkg.get("collection_latency_seconds", 0.0)
    total_latency = round(coll_latency + reasoning_latency, 3)

    # Persist RAG and reasoning metrics into evidence.json for empirical automated extraction
    pkg["rag_query"] = query_str
    pkg["rag_passages"] = retrieved_passages
    pkg["reasoning_latency_seconds"] = reasoning_latency
    pkg["total_latency_seconds"] = total_latency
    with open(evidence_json_path, "w", encoding="utf-8") as f:
        json.dump(pkg, f, indent=2)

    metrics_footer = f"\n\n---\n\n### 📊 Experimental Benchmark Latency Metrics\n" \
                     f"* **Collection Latency ($L_{{\\text{{coll}}}}$):** `{coll_latency}` seconds\n" \
                     f"* **Reasoning Latency ($L_{{\\text{{reason}}}}$):** `{reasoning_latency}` seconds\n" \
                     f"* **Total ForenRAG Latency ($T_{{\\text{{automated}}}}$):** `{total_latency}` seconds\n"

    full_report_content = response + metrics_footer

    # Step 4: Save Report Artifact in same directory as evidence JSON
    if os.path.basename(evidence_json_path) == "evidence.json":
        output_report_path = os.path.join(os.path.dirname(evidence_json_path), "forensic_report.md")
    else:
        output_report_path = evidence_json_path.replace(".json", "_report.md")

    with open(output_report_path, "w", encoding="utf-8") as f:
        f.write(full_report_content)

    print(f"\n[✔] Saved Report Artifact to: {output_report_path}")

    print(f"\n==================================================")
    print(f"   📊 EXPERIMENTAL BENCHMARK LATENCY METRICS")
    print(f"   - Collection Latency (L_coll)  : {coll_latency}s")
    print(f"   - Reasoning Latency (L_reason) : {reasoning_latency}s")
    print(f"   - Total ForenRAG Latency       : {total_latency}s")
    print(f"==================================================\n")

    return full_report_content

if __name__ == "__main__":
    evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_packages")
    json_files = []
    for root, _, files in os.walk(evidence_dir):
        for f in files:
            if f.endswith(".json"):
                json_files.append(os.path.join(root, f))

    if len(sys.argv) > 1:
        test_file = sys.argv[1]
    elif json_files:
        test_file = sorted(json_files)[-1]
    else:
        print("[!] No evidence JSON files found in evidence_packages/")
        sys.exit(1)

    model = sys.argv[2] if len(sys.argv) > 2 else OLLAMA_MODEL
    generate_forensic_report(test_file, model)
