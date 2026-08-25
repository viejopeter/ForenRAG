"""Retrieve knowledge relevant to a forensic evidence package."""

import html
import json
import ntpath
import os
import re
import sys

from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

from technique_inference import derive_technique_metadata

load_dotenv()

CHROMA_DB_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "chroma_db_storage"
)
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_TOP_K = int(os.getenv("RAG_TOP_K", "3"))
DEFAULT_CANDIDATE_MULTIPLIER = int(os.getenv("RAG_CANDIDATE_MULTIPLIER", "4"))

NOISE_BINARIES = {"hostname.exe", "whoami.exe", "cmd.exe", "conhost.exe"}
QUERY_STOP_WORDS = {
    "attack",
    "binaries",
    "command",
    "exe",
    "mitre",
    "rule",
    "technique",
    "the",
    "to",
    "used",
    "using",
    "windows",
}


def _ordered_unique(values):
    """Return non-empty values once while preserving evidence order."""
    return list(dict.fromkeys(value for value in values if value))


def _search_terms(text):
    """Extract procedure-specific terms for lightweight lexical reranking."""
    return {
        token
        for token in re.findall(r"[a-z0-9]+(?:\.[a-z0-9]+)?", text.lower())
        if len(token) > 2 and token not in QUERY_STOP_WORDS
    }


def _rerank_results(results, query_str):
    """Prefer passages that match observed tools and procedures, then vector distance."""
    query_terms = _search_terms(query_str)

    def rank_key(result):
        doc, distance = result
        passage_terms = _search_terms(doc.page_content)
        overlap = len(query_terms & passage_terms)
        return (-overlap, float(distance))

    return sorted(results, key=rank_key)


def _get_vector_store():
    """Initialize the persistent ChromaDB vector store with Ollama embeddings."""
    if not os.path.exists(CHROMA_DB_DIR):
        raise FileNotFoundError(
            f"ChromaDB directory '{CHROMA_DB_DIR}' not found. Run build_chroma_db.py first."
        )

    embedding_function = OllamaEmbeddings(
        model=EMBEDDING_MODEL, base_url=OLLAMA_BASE_URL
    )
    vector_store = Chroma(
        persist_directory=CHROMA_DB_DIR,
        embedding_function=embedding_function,
        collection_name="forenrag_kb",
    )
    return vector_store


def formulate_targeted_query(pkg):
    """Build a retrieval query from collected telemetry."""
    alert = pkg.get("trigger_alert", {})
    rule_desc = alert.get("rule_description", "")
    tree = pkg.get("process_tree", [])
    mitre_ids = _ordered_unique(pkg.get("analysis_techniques", []))
    if not mitre_ids:
        mitre_ids = derive_technique_metadata(alert, tree)["analysis_techniques"]
    cmd_lines = [alert.get("command_line", "")]
    cmd_lines.extend(
        p.get("command_line", "")
        for p in tree
        if ntpath.basename(p.get("image", "")).lower()
        not in {"hostname.exe", "whoami.exe", "conhost.exe"}
    )
    cmd_lines = _ordered_unique(cmd_lines)

    # Evidence contains Windows paths, even when ForenRAG runs on Linux. Using
    # os.path.basename() on Linux leaves backslash-delimited paths unchanged.
    all_image_paths = [p.get("image", "") for p in tree if p.get("image")]
    all_images = [ntpath.basename(path).lower() for path in all_image_paths]
    significant_tools = _ordered_unique(
        img for img in all_images if img not in NOISE_BINARIES
    )

    # Include correlated procedures, not only the triggering command. This helps
    # distinguish different procedures that share the same ATT&CK technique.
    clean_commands = []
    for command in cmd_lines:
        clean_command = re.sub(r'[\\"/&;|><%]+', " ", html.unescape(command))
        clean_command = " ".join(clean_command.split())
        if clean_command:
            clean_commands.append(clean_command)
    clean_cmd = " ; ".join(clean_commands)[:750]

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
    """Retrieve relevant knowledge passages for an evidence package."""
    top_k = top_k or DEFAULT_TOP_K
    if not os.path.exists(evidence_json_path):
        raise FileNotFoundError(
            f"Evidence JSON package file not found: {evidence_json_path}"
        )

    with open(evidence_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    query_str, mitre_ids = formulate_targeted_query(pkg)
    print(f"[+] Formulated Targeted RAG Query:\n    '{query_str}'\n")

    vector_store = _get_vector_store()
    results = []
    candidate_k = max(top_k, top_k * DEFAULT_CANDIDATE_MULTIPLIER)

    primary_mitre = mitre_ids[0] if mitre_ids else None
    if primary_mitre:
        print(f"[+] Attempting Metadata Filter for Technique: '{primary_mitre}'...")
        try:
            filtered_res = vector_store.similarity_search_with_score(
                query_str,
                k=candidate_k,
                filter={"technique": primary_mitre},
            )
            if filtered_res:
                results = _rerank_results(filtered_res, query_str)[:top_k]
                print(
                    f"[+] Metadata Filter Reranked {len(filtered_res)} Candidates "
                    f"and Retained {len(results)} Passages for '{primary_mitre}'"
                )
        except Exception as exc:  # noqa: BLE001 - unfiltered retrieval is the fallback
            print(f"[!] Metadata filter note: {exc}")

    # Use unfiltered candidates only if filtering is unavailable, fails, or
    # returns no passages; a non-empty filtered result is never padded.
    if not results:
        fallback_res = vector_store.similarity_search_with_score(
            query_str, k=candidate_k
        )
        results = _rerank_results(fallback_res, query_str)[:top_k]

    retrieved_passages = []
    print("==================================================")
    print(f"   TOP {len(results)} RETRIEVED KNOWLEDGE PASSAGES FROM CHROMADB")
    print("==================================================")
    for idx, (doc, score) in enumerate(results[:top_k], 1):
        src = doc.metadata.get("source", "Unknown")
        tech = doc.metadata.get("technique", "Generic")
        tech_name = doc.metadata.get("technique_name", "")
        print(
            f"\n--- [Passage {idx} | Source File: {src} | Technique: {tech} | Score: {score:.4f}] ---"
        )
        print(doc.page_content.strip()[:200] + "...")
        retrieved_passages.append(
            {
                "source": os.path.basename(src),
                "technique": tech,
                "technique_name": tech_name,
                "content": doc.page_content.strip(),
                "score": float(score),
            }
        )

    return retrieved_passages, query_str


if __name__ == "__main__":
    evidence_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "evidence_packages"
    )
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
        print("\n==================================================")
        print(
            f"[+] Testing RAG Retrieval for Evidence Package: {os.path.basename(os.path.dirname(tf))}"
        )
        print("==================================================")
        retrieve_rag_context(tf)
