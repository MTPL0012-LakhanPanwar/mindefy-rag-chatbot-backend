"""
Hybrid search retrieval using FAISS and BM25
"""
import numpy as np
import faiss
from typing import List, Tuple
from rank_bm25 import BM25Okapi

class HybridRetriever:
    """Handles hybrid search using FAISS and BM25."""
    
    def __init__(self, chunks: List[str], embedding_service):
        self.chunks = chunks
        self.embedding_service = embedding_service
        self.dense_index = None
        self.bm25_index = None
        self._build_indices()
    
    def _build_indices(self):
        """Build both dense (FAISS) and sparse (BM25) indices."""
        embeddings = self.embedding_service.get_embeddings(self.chunks)
        emb_np = np.array(embeddings).astype('float32')
        dim = emb_np.shape[1]
        
        self.dense_index = faiss.IndexFlatL2(dim)
        self.dense_index.add(emb_np)
        
        tokenized_chunks = [chunk.lower().split() for chunk in self.chunks]
        self.bm25_index = BM25Okapi(tokenized_chunks)
    
    def search(self, query: str, top_k: int = 3) -> List[Tuple[str, float]]:
        """Perform hybrid search combining dense and sparse retrieval."""
        dense_results = self._dense_search(query, top_k)
        sparse_results = self._sparse_search(query, top_k)
        return self._combine_results(dense_results, sparse_results, top_k)
    
    def _dense_search(self, query: str, top_k: int) -> dict:
        """Perform dense vector search using FAISS."""
        q_emb = np.array(
            self.embedding_service.get_embeddings([query])[0], 
            dtype='float32'
        )
        scores, indices = self.dense_index.search(np.array([q_emb]), top_k)
        
        return {
            int(indices[0][i]): 1.0 / (1.0 + float(scores[0][i]))
            for i in range(len(indices[0]))
        }
    
    def _sparse_search(self, query: str, top_k: int) -> dict:
        """Perform sparse keyword search using BM25."""
        tokens = query.lower().split()
        scores = self.bm25_index.get_scores(tokens)
        top_indices = np.argsort(scores)[-top_k:][::-1]
        
        return {
            int(i): float(scores[i])
            for i in top_indices
            if scores[i] > 0
        }
    
    def _combine_results(self, dense: dict, sparse: dict, top_k: int) -> List[Tuple[str, float]]:
        """Combine and rank results from both searches."""
        all_indices = set(dense.keys()) | set(sparse.keys())
        
        combined = [
            (self.chunks[i], dense.get(i, 0.0) + sparse.get(i, 0.0))
            for i in all_indices
        ]
        
        combined.sort(key=lambda x: x[1], reverse=True)
        return combined[:top_k]
