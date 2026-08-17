"""Ingest incident response playbooks into a FAISS vectorstore.

Uses section-aware markdown splitting to ensure each chunk is a complete
section (e.g., the entire "## Containment Actions" block stays together).
Each document carries metadata: playbook_name, section_title, source_file.
"""

import os
import re
import argparse
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

# Define paths relative to the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS_DIR = os.path.join(BASE_DIR, "data", "playbooks")
VECTORSTORE_DIR = os.path.join(BASE_DIR, "data", "vectorstore")

# Regex: match lines starting with one or more '#'
_HEADER_RE = re.compile(r"^(#{1,3})\s+(.+)$", re.MULTILINE)


def _extract_playbook_name(text: str) -> str:
    """Pull the playbook name from the first H1 header."""
    m = re.search(r"^#\s+(?:Incident Response Playbook:\s*)?(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else "Unknown Playbook"


def split_markdown_by_sections(filepath: str) -> list[Document]:
    """Split a single markdown file into one Document per ## section.

    Each Document's page_content contains the section header AND its body.
    Metadata includes playbook_name, section_title, and source_file.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()

    source_file = os.path.basename(filepath)
    playbook_name = _extract_playbook_name(text)

    # Find all header positions
    headers = list(_HEADER_RE.finditer(text))
    if not headers:
        # No headers found — return the whole file as one chunk
        return [Document(
            page_content=text.strip(),
            metadata={
                "playbook_name": playbook_name,
                "section_title": "Full Document",
                "source_file": source_file,
            },
        )]

    documents = []
    for i, match in enumerate(headers):
        level = len(match.group(1))   # 1 for #, 2 for ##, etc.
        title = match.group(2).strip()
        start = match.start()

        # Section runs from this header to the next header of same or higher level
        end = len(text)
        for next_match in headers[i + 1:]:
            next_level = len(next_match.group(1))
            if next_level <= level:
                end = next_match.start()
                break

        section_text = text[start:end].strip()
        if not section_text:
            continue

        documents.append(Document(
            page_content=section_text,
            metadata={
                "playbook_name": playbook_name,
                "section_title": title,
                "source_file": source_file,
                "header_level": level,
            },
        ))

    return documents


def ingest_playbooks():
    print(f"Loading playbooks from {PLAYBOOKS_DIR}...")

    if not os.path.isdir(PLAYBOOKS_DIR):
        print(f"Playbooks directory not found: {PLAYBOOKS_DIR}")
        return

    md_files = [
        os.path.join(PLAYBOOKS_DIR, f)
        for f in sorted(os.listdir(PLAYBOOKS_DIR))
        if f.endswith(".md")
    ]

    if not md_files:
        print("No playbooks found. Please add markdown playbooks to backend/data/playbooks/")
        return

    print(f"Found {len(md_files)} playbook file(s).")

    # Split every playbook into section-level chunks
    all_chunks: list[Document] = []
    for filepath in md_files:
        chunks = split_markdown_by_sections(filepath)
        all_chunks.extend(chunks)

    print(f"\nCreated {len(all_chunks)} section-level chunks:")
    print(f"{'Playbook':<30} {'Section':<30} {'Chars':>6}")
    print("-" * 70)
    for doc in all_chunks:
        pb = doc.metadata["playbook_name"][:28]
        sec = doc.metadata["section_title"][:28]
        chars = len(doc.page_content)
        print(f"{pb:<30} {sec:<30} {chars:>6}")

    print("\nGenerating embeddings and building FAISS index...")
    # Use a fast local embedding model on CPU to avoid conflicting with LM Studio GPU memory
    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2",
        model_kwargs={'device': 'cpu'}
    )

    # Create the FAISS vectorstore
    vectorstore = FAISS.from_documents(all_chunks, embeddings)

    # Ensure vectorstore directory exists
    os.makedirs(VECTORSTORE_DIR, exist_ok=True)

    # Save the index to disk
    vectorstore.save_local(VECTORSTORE_DIR)

    print(f"\nSuccessfully saved FAISS index ({len(all_chunks)} chunks) to {VECTORSTORE_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest incident response playbooks into a FAISS vectorstore."
    )
    args = parser.parse_args()
    ingest_playbooks()
