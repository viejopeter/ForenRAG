"""
ForenRAG Phase 4: Knowledge Retrieval Engine with LangChain, ChromaDB & Ollama
-----------------------------------------------------------------------------
Queries the local ChromaDB vector store using structured telemetry parameters
extracted from Phase 3 Evidence Package JSON files.
"""

import os
import json
import sys
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

CHROMA_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chroma_db_storage")
EMBEDDING_MODEL = "nomic-embed-text"

def get_retriever():
    """Initializes persistent ChromaDB vector store retriever using Ollama embeddings."""
    if not os.path.exists(CHROMA_DB_DIR):
        raise FileNotFoundError(f"ChromaDB directory '{CHROMA_DB_DIR}' not found. Run build_chroma_db.py first.")

    embedding_function = OllamaEmbeddings(model=EMBEDDING_MODEL)
    vector_store = Chroma(
        persist_directory=CHROMA_DB_DIR,
        embedding_function=embedding_function,
        collection_name="forenrag_kb"
    )
    return vector_store

def retrieve_rag_context(evidence_json_path, top_k=3):
    """
    Extracts telemetry parameters from Phase 3 Evidence JSON,
    formulates a RAG query string, and retrieves top_k knowledge passages from ChromaDB.
    """
    if not os.path.exists(evidence_json_path):
        raise FileNotFoundError(f"Evidence JSON package file not found: {evidence_json_path}")

    with open(evidence_json_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    # Extract query formulation parameters
    alert = pkg.get("trigger_alert", {})
    rule_desc = alert.get("rule_description", "")
    mitre_ids = " ".join(alert.get("mitre_id", []))
    
    # Extract unique process images from process tree
    process_tree = pkg.get("process_tree", [])
    process_images = list(set([p.get("image", "").split("\\")[-1] for p in process_tree if p.get("image")]))
    
    # Formulate RAG query string
    query_str = f"Rule: {rule_desc} MITRE: {mitre_ids} Processes: {' '.join(process_images)}"
    print(f"[+] Formulated RAG Query: {query_str}\n")

    # Perform similarity search on ChromaDB
    vector_store = get_retriever()
    results = vector_store.similarity_search_with_score(query_str, k=top_k)

    retrieved_passages = []
    print("==================================================")
    print(f"   TOP {len(results)} RETRIEVED KNOWLEDGE PASSAGES FROM CHROMADB")
    print("==================================================")
    for idx, (doc, score) in enumerate(results, 1):
        src = doc.metadata.get("source", "Unknown")
        print(f"\n--- [Passage {idx} | Source File: {src} | Distance Score: {score:.4f}] ---")
        print(doc.page_content.strip())
        retrieved_passages.append({
            "source": os.path.basename(src),
            "content": doc.page_content.strip(),
            "score": float(score)
        })

    return retrieved_passages, query_str

if __name__ == "__main__":
    # Default test file: latest JSON package in evidence_packages/
    evidence_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_packages")
    json_files = [os.path.join(evidence_dir, f) for f in os.listdir(evidence_dir) if f.endswith(".json")]
    
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
    elif json_files:
        test_file = sorted(json_files)[-1]
    else:
        print("[!] No evidence JSON files found in evidence_packages/")
        sys.exit(1)

    print(f"[+] Processing Evidence Package: {os.path.basename(test_file)}")
    retrieve_rag_context(test_file)
