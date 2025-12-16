"""
LLM service for answer generation
"""
from openai import OpenAI
from typing import List, Dict

class LLMService:
    """Handles answer generation using OpenAI's chat models."""
    
    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.1, max_tokens: int = 500):
        self.client = OpenAI()
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
    
    def generate_answer(self, query: str, context: str, history: List[Dict]) -> str:
        """Generate an answer using the context and conversation history."""
        prompt = self._build_prompt(query, context, history)
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )
        
        return response.choices[0].message.content
    
    def _build_prompt(self, query: str, context: str, history: List[Dict]) -> str:
        """Build the prompt with context and history."""
        history_text = self._format_history(history)
        
        return f"""You are a helpful assistant answering questions about a document. Use the context provided to give accurate, concise answers. If the answer isn't in the context, say so politely.

Context from document:
{context}
{history_text}

Current question: {query}

Provide a clear, engaging answer:"""
    
    @staticmethod
    def _format_history(history: List[Dict]) -> str:
        """Format conversation history."""
        if not history:
            return ""
        
        history_lines = ["\n\nPrevious conversation:"]
        for h in history:
            history_lines.append(f"User: {h['user']}")
            history_lines.append(f"Assistant: {h['assistant']}")
        
        return "\n".join(history_lines)