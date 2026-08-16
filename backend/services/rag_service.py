import os
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORSTORE_DIR = os.path.join(BASE_DIR, "data", "vectorstore")

_vectorstore = None

def get_retriever():
    """
    Loads the FAISS index from disk and returns a retriever.
    Caches the vectorstore in memory to avoid reloading it on every call.
    """
    global _vectorstore
    
    if _vectorstore is None:
        if not os.path.exists(VECTORSTORE_DIR) or not os.listdir(VECTORSTORE_DIR):
            raise FileNotFoundError(
                f"Vectorstore not found at {VECTORSTORE_DIR}. "
                f"Please run backend/scripts/ingest_playbooks.py first."
            )
            
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        # Allow dangerous deserialization because we generated the index locally
        _vectorstore = FAISS.load_local(VECTORSTORE_DIR, embeddings, allow_dangerous_deserialization=True)
        
    return _vectorstore.as_retriever(search_kwargs={"k": 2})
