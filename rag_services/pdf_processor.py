"""
PDF text extraction and chunking
"""
import io
import re
from typing import List
from pypdf import PdfReader
from fastapi import HTTPException

class PDFProcessor:
    """Handles PDF text extraction and chunking."""
    
    @staticmethod
    def extract_text(pdf_bytes: bytes) -> str:
        """Extract and clean text from PDF bytes."""
        try:
            stream = io.BytesIO(pdf_bytes)
            reader = PdfReader(stream)
            
            text_pages = []
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text_pages.append(extracted)
            
            full_text = "\n".join(text_pages)
            return PDFProcessor._clean_text(full_text)
            
        except Exception as e:
            raise HTTPException(
                status_code=400, 
                detail=f"Failed to extract text from PDF: {str(e)}"
            )
    
    @staticmethod
    def _clean_text(text: str) -> str:
        """Clean and normalize text."""
        text = re.sub(r"-\s*\n", "", text)
        text = text.replace("\n", " ")
        text = re.sub(r"\s+", " ", text).strip()
        return text
    
    @staticmethod
    def create_chunks(text: str, chunk_size: int, overlap: int) -> List[str]:
        if not text:
            return []
        
        if overlap >= chunk_size:
            raise ValueError("overlap must be smaller than chunk_size")

        chunks = []
        start = 0
        text_len = len(text)
        
        while start < text_len:
            end = min(start + chunk_size, text_len)
            chunks.append(text[start:end])

            # prevent infinite backward looping
            next_start = end - overlap
            if next_start <= start:
                break
            
            start = next_start
        
        return chunks