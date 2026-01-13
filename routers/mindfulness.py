# routers/mindfulness.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from mindfulnest_api import MindfulNestRAG, setup_logger

# ------------------------------------------------------------------
# Router setup
# ------------------------------------------------------------------

router = APIRouter(
    prefix="/mindfulness",
    tags=["Mindfulness RAG"]
)

logger = setup_logger("mindfulness-api")

# ------------------------------------------------------------------
# Initialize RAG system (singleton)
# ------------------------------------------------------------------

try:
    rag_system = MindfulNestRAG()
    logger.info("MindfulNest RAG initialized successfully")
except Exception as e:
    logger.exception("Failed to initialize MindfulNest RAG")
    raise


# ------------------------------------------------------------------
# Request / Response Schemas
# ------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@router.get("/")
def home():
    return {
        "status": "running",
        "service": "MindfulNest API",
        "version": "1.0.0",
        "endpoints": {
            "POST /mindfulness/chat": "Send a message",
            "POST /mindfulness/reset": "Clear conversation history",
            "GET /mindfulness/stats": "Get system statistics",
            "GET /mindfulness/health": "Check system health"
        }
    }


@router.get("/health")
def health():
    try:
        stats = rag_system.get_stats()
        return {
            "status": "healthy",
            "rag_initialized": True,
            "stats": stats
        }
    except Exception as e:
        logger.exception("Health check failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/chat")
def chat(payload: ChatRequest):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    try:
        result = rag_system.query(
            payload.message.strip(),
            session_id=payload.session_id
        )
        return result
    except Exception as e:
        logger.exception("Error in chat endpoint")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/reset")
def reset():
    try:
        rag_system.reset_conversation()
        return {
            "success": True,
            "message": "Conversation history cleared"
        }
    except Exception as e:
        logger.exception("Reset failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
def stats():
    try:
        return {
            "success": True,
            "stats": rag_system.get_stats()
        }
    except Exception as e:
        logger.exception("Stats fetch failed")
        raise HTTPException(status_code=500, detail=str(e))
