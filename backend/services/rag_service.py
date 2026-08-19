"""RAG service — loads the FAISS vectorstore and provides playbook retrieval.

Supports two retrieval modes:
- `get_retriever()` — backward-compatible LangChain retriever.
- `search_playbook()` — section-aware search with optional classification filtering
  and section-priority ranking.
"""

import os
import logging
from typing import List, Optional

from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

logger = logging.getLogger("rag-service")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORSTORE_DIR = os.path.join(BASE_DIR, "data", "vectorstore")

_vectorstore: Optional[FAISS] = None

# Priority ordering for sections — higher index = more relevant for response planning
_SECTION_PRIORITY = {
    "containment actions": 4,
    "eradication & recovery": 3,
    "eradication and recovery": 3,
    "triage & investigation": 2,
    "triage and investigation": 2,
    "description": 1,
    "post-incident": 0,
}

# Map alert classifications to playbook names for metadata filtering
_CLASSIFICATION_TO_PLAYBOOK = {
    "malware_execution": "Malware Execution",
    "malware": "Malware Execution",
    "ransomware": "Malware Execution",
    "lateral_movement": "Lateral Movement",
    "data_exfiltration": "Data Exfiltration",
    "exfiltration": "Data Exfiltration",
    "phishing": "Phishing Response",
    "phishing_response": "Phishing Response",
    "credential_compromise": "Lateral Movement",
}


def _load_vectorstore() -> FAISS:
    """Load and cache the FAISS vectorstore from disk."""
    global _vectorstore

    if _vectorstore is None:
        if not os.path.exists(VECTORSTORE_DIR) or not os.listdir(VECTORSTORE_DIR):
            raise FileNotFoundError(
                f"Vectorstore not found at {VECTORSTORE_DIR}. "
                f"Please run backend/scripts/ingest_playbooks.py first."
            )

        embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'}
        )
        _vectorstore = FAISS.load_local(
            VECTORSTORE_DIR, embeddings, allow_dangerous_deserialization=True
        )
        logger.info("Loaded FAISS vectorstore from %s", VECTORSTORE_DIR)

    return _vectorstore


def get_retriever():
    """Backward-compatible retriever for general use."""
    vs = _load_vectorstore()
    return vs.as_retriever(search_kwargs={"k": 4})


def search_playbook(
    query: str,
    classification: Optional[str] = None,
    k: int = 20,
) -> List[Document]:
    """Section-aware playbook retrieval with optional classification filtering.

    Args:
        query: The semantic search query (e.g., root cause description).
        classification: Optional alert classification (e.g., 'malware_execution')
                        used to prioritize the matching playbook.
        k: Number of candidate chunks to retrieve before filtering/ranking.

    Returns:
        List of Documents sorted by relevance:
        1. Matching playbook's Containment/Eradication sections first
        2. Other playbooks' relevant sections second
    """
    vs = _load_vectorstore()

    # Retrieve candidates via similarity search
    candidates = vs.similarity_search(query, k=k)

    if not candidates:
        logger.warning("No RAG results for query: %s", query[:100])
        return []

    # Resolve the target playbook name from classification
    target_playbook = None
    if classification:
        classification_lower = classification.lower().strip()
        target_playbook = _CLASSIFICATION_TO_PLAYBOOK.get(classification_lower)
        if not target_playbook:
            # Try partial matching
            for key, name in _CLASSIFICATION_TO_PLAYBOOK.items():
                if key in classification_lower or classification_lower in key:
                    target_playbook = name
                    break

    # De-duplicate by (playbook_name, section_title)
    seen = set()
    unique_docs = []
    for doc in candidates:
        key = (
            doc.metadata.get("playbook_name", ""),
            doc.metadata.get("section_title", ""),
        )
        if key not in seen:
            seen.add(key)
            unique_docs.append(doc)

    # Score and sort
    def _sort_key(doc: Document) -> tuple:
        meta = doc.metadata
        playbook_name = meta.get("playbook_name", "")
        section_title = meta.get("section_title", "").lower()

        # Playbook match score: 1 if matches classification, 0 otherwise
        playbook_match = 1 if (target_playbook and target_playbook in playbook_name) else 0

        # Section priority score
        section_score = 0
        for pattern, priority in _SECTION_PRIORITY.items():
            if pattern in section_title:
                section_score = priority
                break

        # Sort descending by (playbook_match, section_priority)
        return (-playbook_match, -section_score)

    unique_docs.sort(key=_sort_key)

    logger.info(
        "RAG search: query=%s, classification=%s, target_playbook=%s, results=%d",
        query[:60], classification, target_playbook, len(unique_docs),
    )
    for doc in unique_docs:
        logger.debug(
            "  -> [%s] %s (%d chars)",
            doc.metadata.get("playbook_name", "?"),
            doc.metadata.get("section_title", "?"),
            len(doc.page_content),
        )

    return unique_docs
