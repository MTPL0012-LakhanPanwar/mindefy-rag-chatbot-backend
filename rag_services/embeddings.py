"""
Embedding generation service using OpenAI
"""
from typing import List
from openai import OpenAI

class EmbeddingService:
    """Handles embedding generation using OpenAI."""
    
    def __init__(self, model: str = "text-embedding-3-small"):
        # Delay OpenAI client construction until first use so importing
        # modules does not fail when OPENAI_API_KEY is not set.
        self._client = None
        self.model = model

    def _ensure_client(self):
        if self._client is None:
            try:
                self._client = OpenAI()
            except Exception as e:
                # Provide a clear runtime error explaining what's missing
                raise RuntimeError(
                    "OpenAI client could not be initialized. "
                    "Set the OPENAI_API_KEY environment variable or pass an API key to the client." 
                    f"Original error: {e}"
                )
    
    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts."""
        # initialize client if needed (will raise RuntimeError if missing)
        self._ensure_client()
        response = self._client.embeddings.create(
            model=self.model,
            input=texts
        )
        return [d.embedding for d in response.data]
