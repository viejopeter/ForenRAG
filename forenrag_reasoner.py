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
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from forenrag_retriever import retrieve_rag_context

DEFAULT_MODEL = "gemma4:e2b"

def format_evidence_summary(pkg):
    """Formats raw Sysmon JSON payload into structured text blocks for strictly grounded telemetry LLM reasoning."""
    alert = pkg.get("trigger_alert", {})
    tree = pkg.get("process_tree", [])
    artifacts = pkg.get("artifacts", {})
    
    summary_lines = [
        f"- Trigger Rule: {alert.get('rule_description')} (Rule Level {alert.get('rule_level')})",
        f"- MITRE Technique IDs: {', '.join(alert.get('mitre_id', []))}",
        f"- Trigger Timestamp: {alert.get('timestamp')}",
        "\n--- Process Execution Lineage ---"
    ]
    
    for proc in tree:
        summary_lines.append(
            f"  * PID {proc.get('process_id')} | Image: {proc.get('image')} | User: {proc.get('user')} | Integrity: {proc.get('integrity_level')}\n"
            f"    CmdLine: {proc.get('command_line')}\n"
            f"    Hashes: {proc.get('hashes')}"
        )
        
    summary_lines.append("\n--- File Creation Artifacts ---")
    for f in artifacts.get("file_creations", []):
        summary_lines.append(f"  * File Dropped: {f.get('target_filename')} by Process: {f.get('image')}")
        
    summary_lines.append("\n--- Registry Modification Artifacts ---")
    for r in artifacts.get("registry_sets", []):
        summary_lines.append(f"  * Target Registry: {r.get('target_object')} | Details: {r.get('details')}")
        
    return "\n".join(summary_lines)

def generate_forensic_report(evidence_json_path, model_name=DEFAULT_MODEL):
    """
    Ingests Phase 3 JSON evidence + Phase 4 RAG retrieved context,
    invokes local Ollama LLM, and generates an explainable DFIR report.
    """
    if not os.path.exists(evidence_json_path):
        raise FileNotFoundError(f"Evidence JSON file not found: {evidence_json_path}")

    start_t = time.time()
    print(f"\n==================================================")
    print(f"   ForenRAG Phase 5 Investigation Reasoning Engine")
    print(f"   Target Evidence Package: {evidence_json_path}")
    print(f"   Ollama Local LLM Model: {model_name}")
    print(f"==================================================\n")

    # Step 1: Retrieve RAG Knowledge Context from ChromaDB (Phase 4)
    retrieved_passages, query_str = retrieve_rag_context(evidence_json_path, top_k=3)
    kb_context = "\n\n".join([f"--- Knowledge Chunk ({p['source']}) ---\n{p['content']}" for p in retrieved_passages])

    # Step 2: Read Evidence Package JSON & Format Text Summary
    with open(evidence_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    evidence_text = format_evidence_summary(pkg)

    # Step 3: Define Explainable DFIR Grounding Prompt Template
    prompt_template = """You are ForenRAG, an expert Digital Forensics and Incident Response (DFIR) AI Analyst.
Analyze the following endpoint evidence summary and retrieved threat intelligence context.
Generate a professional, explainable DFIR investigation report.

COLLECTED EVIDENCE SUMMARY:
{evidence_text}

RETRIEVED THREAT INTELLIGENCE (RAG CONTEXT):
{rag_context}

Provide a structured report with:
1. Executive Summary & Severity Rating
2. Attack Timeline & Process Lineage Analysis (Markdown Table)
3. Evidence Traceability (Files/Registry dropped)
4. MITRE ATT&CK Mapping & LOLBAS Identification
5. Recommended Response & Remediation Playbook

FORENSIC REPORT:"""

    prompt = PromptTemplate(
        input_variables=["evidence_text", "rag_context"],
        template=prompt_template
    )

    print(f"\n[+] Invoking Ollama LLM Model '{model_name}' via LangChain...")
    llm = OllamaLLM(model=model_name, temperature=0.1, num_ctx=8192, num_predict=4096)

    formatted_prompt = prompt.format(
        evidence_text=evidence_text,
        rag_context=kb_context
    )

    response = llm.invoke(formatted_prompt)

    print("\n==================================================")
    print("   GENERATED EXPLAINABLE FORENSIC INVESTIGATION REPORT")
    print("==================================================\n")
    print(response)

    reasoning_latency = round(time.time() - start_t, 3)
    coll_latency = pkg.get("collection_latency_seconds", 0.0)
    total_latency = round(coll_latency + reasoning_latency, 3)

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

    model = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MODEL
    generate_forensic_report(test_file, model)
