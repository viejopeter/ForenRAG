"""
ForenRAG Phase 4: Knowledge Retrieval Engine with LangChain, ChromaDB & Ollama
-----------------------------------------------------------------------------
Queries the local ChromaDB vector store using targeted telemetry parameters
and MITRE technique metadata filtering to eliminate off-target retrieval noise.
"""

import os
import ntpath
import json
import sys
import re
from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from technique_inference import derive_technique_metadata

load_dotenv()

CHROMA_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chroma_db_storage")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_TOP_K = int(os.getenv("RAG_TOP_K", "3"))

NOISE_BINARIES = {"hostname.exe", "whoami.exe", "cmd.exe", "conhost.exe"}

def _ordered_unique(values):
    """Return non-empty values once while preserving evidence order."""
    return list(dict.fromkeys(value for value in values if value))

def get_retriever():
    """Initializes persistent ChromaDB vector store retriever using Ollama embeddings."""
    if not os.path.exists(CHROMA_DB_DIR):
        raise FileNotFoundError(f"ChromaDB directory '{CHROMA_DB_DIR}' not found. Run build_chroma_db.py first.")

    embedding_function = OllamaEmbeddings(model=EMBEDDING_MODEL, base_url=OLLAMA_BASE_URL)
    vector_store = Chroma(
        persist_directory=CHROMA_DB_DIR,
        embedding_function=embedding_function,
        collection_name="forenrag_kb"
    )
    return vector_store

def formulate_targeted_query(pkg):
    """Formulates a clean, focused, noise-filtered search query from telemetry JSON."""
    alert = pkg.get("trigger_alert", {})
    rule_desc = alert.get("rule_description", "")
    tree = pkg.get("process_tree", [])
    mitre_ids = _ordered_unique(pkg.get("analysis_techniques", []))
    if not mitre_ids:
        mitre_ids = derive_technique_metadata(alert, tree)["analysis_techniques"]
    cmd_line = alert.get("command_line", "")
    
    # Evidence contains Windows paths, even when ForenRAG runs on Linux. Using
    # os.path.basename() on Linux leaves backslash-delimited paths unchanged.
    all_image_paths = [p.get("image", "") for p in tree if p.get("image")]
    all_images = [ntpath.basename(path).lower() for path in all_image_paths]
    significant_tools = _ordered_unique(img for img in all_images if img not in NOISE_BINARIES)
    
    clean_cmd = re.sub(r'[\\"/]', ' ', cmd_line)[:100]

    mitre_str = " ".join(mitre_ids)
    tools_str = " ".join(significant_tools)
    
    query_parts = []
    if mitre_str:
        query_parts.append(f"MITRE Technique {mitre_str}")
    if rule_desc:
        query_parts.append(f"Rule: {rule_desc}")
    if tools_str:
        query_parts.append(f"Attack Binaries: {tools_str}")
    if clean_cmd:
        query_parts.append(f"Command Arguments: {clean_cmd}")

    return " | ".join(query_parts), mitre_ids

def retrieve_rag_context(evidence_json_path, top_k=None):
    """
    Extracts telemetry parameters from Phase 3 Evidence JSON,
    formulates a targeted RAG query, and retrieves top_k knowledge passages from ChromaDB
    using technique metadata filtering to ensure 100% relevant context.
    """
    top_k = top_k or DEFAULT_TOP_K
    if not os.path.exists(evidence_json_path):
        raise FileNotFoundError(f"Evidence JSON package file not found: {evidence_json_path}")

    with open(evidence_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    query_str, mitre_ids = formulate_targeted_query(pkg)
    print(f"[+] Formulated Targeted RAG Query:\n    '{query_str}'\n")

    vector_store = get_retriever()
    results = []

    # Attempt metadata filtering using primary MITRE technique ID
    primary_mitre = mitre_ids[0] if mitre_ids else None
    if primary_mitre:
        print(f"[+] Attempting Metadata Filter for Technique: '{primary_mitre}'...")
        try:
            filtered_res = vector_store.similarity_search_with_score(query_str, k=top_k, filter={"technique": primary_mitre})
            if filtered_res:
                results = filtered_res
                print(f"[✔] Metadata Filter Retained {len(results)} Direct Match Passages for '{primary_mitre}'")
        except Exception as e:
            print(f"[!] Metadata filter note: {e}")

    # Fallback to unguided similarity search if filter returned fewer than top_k
    if len(results) < top_k:
        fallback_res = vector_store.similarity_search_with_score(query_str, k=top_k)
        for doc, score in fallback_res:
            if not any(doc.page_content == existing[0].page_content for existing in results):
                results.append((doc, score))
            if len(results) >= top_k:
                break

    retrieved_passages = []
    print("==================================================")
    print(f"   TOP {len(results)} RETRIEVED KNOWLEDGE PASSAGES FROM CHROMADB")
    print("==================================================")
    for idx, (doc, score) in enumerate(results[:top_k], 1):
        src = doc.metadata.get("source", "Unknown")
        tech = doc.metadata.get("technique", "Generic")
        print(f"\n--- [Passage {idx} | Source File: {src} | Technique: {tech} | Score: {score:.4f}] ---")
        print(doc.page_content.strip()[:200] + "...")
        retrieved_passages.append({
            "source": os.path.basename(src),
            "technique": tech,
            "content": doc.page_content.strip(),
            "score": float(score)
        })

    return retrieved_passages, query_str

if __name__ == "__main__":
    evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_packages")
    json_files = []
    for root, _, files in os.walk(evidence_dir):
        for f in files:
            if f.endswith(".json"):
                json_files.append(os.path.join(root, f))
    
    if len(sys.argv) > 1:
        test_files = [sys.argv[1]]
    else:
        test_files = sorted(json_files)

    for tf in test_files:
        print(f"\n==================================================")
        print(f"[+] Testing RAG Retrieval for Evidence Package: {os.path.basename(os.path.dirname(tf))}")
        print(f"==================================================")
        retrieve_rag_context(tf)
