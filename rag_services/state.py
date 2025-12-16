"""
Shared in-memory state for RAG features.

This keeps the retriever, chunks and uploaded PDF metadata in one place
so both admin upload endpoints and chat endpoints see the same data.
"""

# Using a simple dict as a lightweight in-memory store.
global_state = {
    "retriever": None,
    "chunks": None,
    "history": [],
    "pdf_path": None,
    "pdf_filename": None,
    "pdf_size": None,
}

