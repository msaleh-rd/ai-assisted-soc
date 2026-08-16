import os
import argparse
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

# Define paths relative to the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS_DIR = os.path.join(BASE_DIR, "data", "playbooks")
VECTORSTORE_DIR = os.path.join(BASE_DIR, "data", "vectorstore")

def ingest_playbooks():
    print(f"Loading playbooks from {PLAYBOOKS_DIR}...")
    
    # Load all markdown files from the playbooks directory
    # Ensure TextLoader uses utf-8 encoding for markdown files
    loader = DirectoryLoader(PLAYBOOKS_DIR, glob="**/*.md", loader_cls=TextLoader, loader_kwargs={'autodetect_encoding': True})
    documents = loader.load()
    
    if not documents:
        print("No playbooks found. Please add markdown playbooks to backend/data/playbooks/")
        return

    print(f"Loaded {len(documents)} playbooks. Chunking...")
    
    # Chunk the documents to fit into LLM context and improve retrieval accuracy
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=100,
        length_function=len,
        add_start_index=True,
    )
    chunks = text_splitter.split_documents(documents)
    print(f"Created {len(chunks)} chunks.")

    print("Generating embeddings and building FAISS index...")
    # Use a fast local embedding model
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    # Create the FAISS vectorstore
    vectorstore = FAISS.from_documents(chunks, embeddings)
    
    # Ensure vectorstore directory exists
    os.makedirs(VECTORSTORE_DIR, exist_ok=True)
    
    # Save the index to disk
    vectorstore.save_local(VECTORSTORE_DIR)
    
    print(f"Successfully saved FAISS index to {VECTORSTORE_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest incident response playbooks into a FAISS vectorstore.")
    args = parser.parse_args()
    ingest_playbooks()
