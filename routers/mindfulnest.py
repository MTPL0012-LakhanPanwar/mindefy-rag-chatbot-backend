from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from mindfulnest_api import MindfulNestRAG, setup_logger


logger = setup_logger("mindfulnest_api")


router = APIRouter(prefix="/mindfulnest", tags=["mindfulnest"])


class MindfulNestChatRequest(BaseModel):
    message: str


@lru_cache(maxsize=1)
def get_mindfulnest_rag() -> MindfulNestRAG:
    """
    Lazily initialize a single MindfulNestRAG instance.

    This mirrors the original Flask app behaviour where the RAG engine
    is created once at startup and reused for all requests.
    """
    try:
        return MindfulNestRAG()
    except Exception as exc:  # pragma: no cover - fatal startup path
        logger.error("Failed to initialize MindfulNest RAG: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="MindfulNest RAG system failed to initialize",
        )


@router.get("/", summary="MindfulNest API info")
async def mindfulnest_home() -> Dict[str, Any]:
    """Basic info endpoint similar to the original Flask '/' route."""
    return {
        "status": "running",
        "service": "MindfulNest API",
        "version": "1.0.0",
        "endpoints": {
            "POST /mindfulnest/chat": "Send a message and get response",
            "POST /mindfulnest/reset": "Clear conversation history",
            "GET /mindfulnest/stats": "Get system statistics",
            "GET /mindfulnest/health": "Check system health",
        },
    }


@router.get("/health", summary="MindfulNest health check")
async def mindfulnest_health(
    rag: MindfulNestRAG = Depends(get_mindfulnest_rag),
) -> Dict[str, Any]:
    """Detailed health check using MindfulNestRAG stats."""
    try:
        stats = rag.get_stats()
        return {
            "status": "healthy",
            "rag_initialized": True,
            "stats": stats,
        }
    except Exception as exc:
        logger.error("MindfulNest health check failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="MindfulNest health check failed",
        )


@router.post("/chat", summary="MindfulNest chat")
async def mindfulnest_chat(
    payload: MindfulNestChatRequest,
    rag: MindfulNestRAG = Depends(get_mindfulnest_rag),
) -> Dict[str, Any]:
    """
    Main MindfulNest chat endpoint.

    Mirrors the Flask `/chat` endpoint but exposed via FastAPI.
    """
    try:
        user_message = payload.message.strip()
        if not user_message:
            raise HTTPException(
                status_code=400,
                detail="Message cannot be empty",
            )

        result = rag.query(user_message)
        return result
    except HTTPException:
        # Re-raise HTTP errors unchanged
        raise
    except Exception as exc:
        logger.error("Error in MindfulNest chat endpoint: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Internal server error",
        )


@router.post("/reset", summary="Reset MindfulNest conversation")
async def mindfulnest_reset(
    rag: MindfulNestRAG = Depends(get_mindfulnest_rag),
) -> Dict[str, Any]:
    """Reset MindfulNest shared conversation history."""
    try:
        rag.reset_conversation()
        return {
            "success": True,
            "message": "Conversation history cleared",
        }
    except Exception as exc:
        logger.error("Error resetting MindfulNest conversation: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to reset conversation history",
        )


@router.get("/stats", summary="MindfulNest statistics")
async def mindfulnest_stats(
    rag: MindfulNestRAG = Depends(get_mindfulnest_rag),
) -> Dict[str, Any]:
    """Get MindfulNest system statistics."""
    try:
        statistics = rag.get_stats()
        return {
            "success": True,
            "stats": statistics,
        }
    except Exception as exc:
        logger.error("Error getting MindfulNest stats: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to get MindfulNest stats",
        )

