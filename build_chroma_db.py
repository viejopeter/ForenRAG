"""
ForenRAG Phase 4: Knowledge Base Indexer with LangChain, ChromaDB & Ollama
-------------------------------------------------------------------------
Builds a persistent local vector store using ChromaDB, LangChain, and Ollama.
Splits official threat intelligence documents into structured chunks and computes
embeddings via nomic-embed-text with standardized MITRE technique metadata tags.
"""

import os
import re
import shutil
from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

load_dotenv()

KB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge_base")
CHROMA_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chroma_db_storage")

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
CHUNK_SIZE = int(os.getenv("CHROMA_CHUNK_SIZE", "1000"))
CHUNK_OVERLAP = int(os.getenv("CHROMA_CHUNK_OVERLAP", "150"))

def extract_technique_id(filename, content):
    """Standardizes MITRE ATT&CK technique IDs (e.g. T1003.002, T1059.001) from filename or content."""
    fn_match = re.search(r"t(\d{4}(?:[_\.]\d{3})?)", filename.lower())
    if fn_match:
        raw_id = fn_match.group(1).upper().replace("_", ".")
        return f"T{raw_id}"
    
    content_match = re.search(r"T\d{4}(?:\.\d{3})?", content)
    if content_match:
        return content_match.group(0)
    return "GENERIC"

def build_vector_store():
    print(f"[+] Loading knowledge base documents from: {KB_DIR}")
    if not os.path.exists(KB_DIR):
        raise FileNotFoundError(f"Knowledge base directory '{KB_DIR}' does not exist.")

    raw_documents = []
    for fname in sorted(os.listdir(KB_DIR)):
        if fname.endswith((".md", ".yml", ".yaml")):
            fpath = os.path.join(KB_DIR, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
                tech_id = extract_technique_id(fname, content)
                raw_documents.append(Document(
                    page_content=content,
                    metadata={"source": fname, "technique": tech_id}
                ))
        
    print(f"[+] Loaded {len(raw_documents)} raw document files.")

    # Structured chunking preserving heading context (1000 chars)
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n# ", "\n## ", "\n### ", "\n\n", "\n", " "]
    )
    docs = text_splitter.split_documents(raw_documents)
    print(f"[+] Split knowledge base into {len(docs)} text chunks (Chunk Size={CHUNK_SIZE}, Overlap={CHUNK_OVERLAP}).")

    print(f"[+] Initializing Ollama local embedding model '{EMBEDDING_MODEL}' at {OLLAMA_BASE_URL} ...")
    embedding_function = OllamaEmbeddings(model=EMBEDDING_MODEL, base_url=OLLAMA_BASE_URL)

    print(f"[+] Indexing knowledge chunks into ChromaDB at: {CHROMA_DB_DIR} ...")
    
    if os.path.exists(CHROMA_DB_DIR):
        shutil.rmtree(CHROMA_DB_DIR)

    vector_store = Chroma.from_documents(
        documents=docs,
        embedding=embedding_function,
        persist_directory=CHROMA_DB_DIR,
        collection_name="forenrag_kb"
    )

    print(f"[✔] Successfully indexed {len(docs)} chunks into ChromaDB ('forenrag_kb') using Ollama '{EMBEDDING_MODEL}'!")
    return vector_store

if __name__ == "__main__":
    build_vector_store()
