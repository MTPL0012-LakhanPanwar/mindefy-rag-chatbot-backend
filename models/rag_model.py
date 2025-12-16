"""
Pydantic models for API requests and responses
"""
from pydantic import BaseModel
from typing import List, Optional

class ChatRequest(BaseModel):
    message: str  # REMOVED session_id field

class ChatResponse(BaseModel):
    answer: str
    sources: List[str]
    # REMOVED session_id field

class UploadResponse(BaseModel):
    message: str
    chunks_count: int
    is_update: bool = False
    previous_chunks: Optional[int] = None
    filename: str  # PDF filename
    file_size: int  # PDF size in bytes

class HealthResponse(BaseModel):
    status: str
    has_document: bool
    chunks_count: int
    filename: Optional[str] = None
    file_size: Optional[int] = None  # PDF size in bytes