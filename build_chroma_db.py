"""Build the local ChromaDB knowledge index."""

import os
import re
import shutil

from chromadb import PersistentClient
from dotenv import load_dotenv
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

load_dotenv()

KB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge_base")
CHROMA_DB_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "chroma_db_storage"
)
CHROMA_STAGING_DIR = f"{CHROMA_DB_DIR}.staging"
CHROMA_BACKUP_DIR = f"{CHROMA_DB_DIR}.backup"

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
CHUNK_SIZE = int(os.getenv("CHROMA_CHUNK_SIZE", "1000"))
CHUNK_OVERLAP = int(os.getenv("CHROMA_CHUNK_OVERLAP", "150"))


def _remove_build_artifact(path):
    """Remove only a controlled staging or backup path without following symlinks."""
    if path not in {CHROMA_STAGING_DIR, CHROMA_BACKUP_DIR}:
        raise ValueError(f"Refusing to remove uncontrolled path: {path}")

    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        raise OSError(f"Unsupported build artifact at: {path}")


def _prepare_build_paths():
    """Recover an interrupted swap and remove stale controlled artifacts."""
    if os.path.lexists(CHROMA_BACKUP_DIR):
        if os.path.islink(CHROMA_BACKUP_DIR) or not os.path.isdir(CHROMA_BACKUP_DIR):
            raise OSError(
                f"ChromaDB backup is not a regular directory: {CHROMA_BACKUP_DIR}"
            )
        if os.path.lexists(CHROMA_DB_DIR):
            if os.path.islink(CHROMA_DB_DIR) or os.path.isfile(CHROMA_DB_DIR):
                os.unlink(CHROMA_DB_DIR)
            elif os.path.isdir(CHROMA_DB_DIR):
                shutil.rmtree(CHROMA_DB_DIR)
            else:
                raise OSError(f"Unsupported live index at: {CHROMA_DB_DIR}")
        os.replace(CHROMA_BACKUP_DIR, CHROMA_DB_DIR)

    _remove_build_artifact(CHROMA_STAGING_DIR)


def _activate_staged_index(embedding_function, expected_count):
    """Activate the validated staged index and restore the previous one on failure."""
    had_current_index = os.path.lexists(CHROMA_DB_DIR)
    if had_current_index:
        os.replace(CHROMA_DB_DIR, CHROMA_BACKUP_DIR)

    try:
        os.replace(CHROMA_STAGING_DIR, CHROMA_DB_DIR)
    except OSError as swap_error:
        if had_current_index:
            try:
                os.replace(CHROMA_BACKUP_DIR, CHROMA_DB_DIR)
            except OSError as rollback_error:
                raise RuntimeError(
                    "Failed to activate the staged ChromaDB index and failed to "
                    f"restore the previous index from '{CHROMA_BACKUP_DIR}': "
                    f"{rollback_error}"
                ) from swap_error
        raise

    live_client = None
    try:
        live_client = PersistentClient(path=CHROMA_DB_DIR)
        vector_store = Chroma(
            persist_directory=CHROMA_DB_DIR,
            embedding_function=embedding_function,
            collection_name="forenrag_kb",
            client=live_client,
        )
        live_count = live_client.get_collection("forenrag_kb").count()
        if live_count != expected_count:
            raise RuntimeError(
                f"Activated ChromaDB validation failed: expected {expected_count} "
                f"chunks, found {live_count}."
            )
    except Exception as activation_error:
        if live_client is not None:
            live_client.close()
        try:
            os.replace(CHROMA_DB_DIR, CHROMA_STAGING_DIR)
            if had_current_index:
                os.replace(CHROMA_BACKUP_DIR, CHROMA_DB_DIR)
        except OSError as rollback_error:
            raise RuntimeError(
                "Activated ChromaDB validation failed and the previous index could "
                f"not be restored from '{CHROMA_BACKUP_DIR}': {rollback_error}"
            ) from activation_error
        raise

    if had_current_index:
        try:
            _remove_build_artifact(CHROMA_BACKUP_DIR)
        except OSError as cleanup_error:
            print(f"[!] Could not remove stale ChromaDB backup: {cleanup_error}")

    return vector_store


def extract_technique_id(filename, content):
    """Extract and normalize an ATT&CK technique ID."""
    fn_match = re.search(r"t(\d{4}(?:[_\.]\d{3})?)", filename.lower())
    if fn_match:
        raw_id = fn_match.group(1).upper().replace("_", ".")
        return f"T{raw_id}"

    content_match = re.search(r"T\d{4}(?:\.\d{3})?", content)
    if content_match:
        return content_match.group(0)
    return "GENERIC"


def extract_technique_name(technique_id, content):
    """Extract the canonical name paired with a technique ID in a document heading."""
    heading_match = re.search(
        rf"^#\s+{re.escape(technique_id)}\s+-\s+(.+?)\s*$",
        content,
        flags=re.MULTILINE,
    )
    return heading_match.group(1).strip() if heading_match else ""


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
            tech_name = extract_technique_name(tech_id, content)
            raw_documents.append(
                Document(
                    page_content=content,
                    metadata={
                        "source": fname,
                        "technique": tech_id,
                        "technique_name": tech_name,
                    },
                )
            )

    print(f"[+] Loaded {len(raw_documents)} raw document files.")

    # Structured chunking preserves heading context at the configured size.
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n# ", "\n## ", "\n### ", "\n\n", "\n", " "],
    )
    docs = text_splitter.split_documents(raw_documents)
    print(
        f"[+] Split knowledge base into {len(docs)} text chunks (Chunk Size={CHUNK_SIZE}, Overlap={CHUNK_OVERLAP})."
    )

    print(
        f"[+] Initializing Ollama local embedding model '{EMBEDDING_MODEL}' at {OLLAMA_BASE_URL} ..."
    )
    embedding_function = OllamaEmbeddings(
        model=EMBEDDING_MODEL, base_url=OLLAMA_BASE_URL
    )

    _prepare_build_paths()
    print(f"[+] Building replacement ChromaDB index at: {CHROMA_STAGING_DIR} ...")

    try:
        staging_client = PersistentClient(path=CHROMA_STAGING_DIR)
        try:
            Chroma.from_documents(
                documents=docs,
                embedding=embedding_function,
                persist_directory=CHROMA_STAGING_DIR,
                collection_name="forenrag_kb",
                client=staging_client,
            )
            staged_count = staging_client.get_collection("forenrag_kb").count()
            if not os.path.isdir(CHROMA_STAGING_DIR) or staged_count != len(docs):
                raise RuntimeError(
                    f"Staged ChromaDB validation failed: expected {len(docs)} "
                    f"chunks, found {staged_count}."
                )
        finally:
            staging_client.close()

        vector_store = _activate_staged_index(embedding_function, len(docs))
    finally:
        _remove_build_artifact(CHROMA_STAGING_DIR)

    print(
        f"[+] Successfully indexed {len(docs)} chunks into ChromaDB ('forenrag_kb') using Ollama '{EMBEDDING_MODEL}'."
    )
    return vector_store


if __name__ == "__main__":
    build_vector_store()
