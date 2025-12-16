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
        
        return f"""You are an intelligent and friendly assistant that helps users understand and explore the content of the uploaded PDF.

                Your job is to answer questions only using the information from the document. If the answer is not present, clearly say you couldn't find it in the PDF.

                Explain things in a clear, conversational, and easy-to-understand way, adapting the depth based on the user's question.

                When helpful, summarize, simplify complex sections, or guide the user to the relevant part of the document.

                Be engaging, natural, and supportive—like a knowledgeable guide helping someone read the document, not a textbook.

                Context from document:
                {context}
                {history_text}

                Current question: {query}"""
    
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