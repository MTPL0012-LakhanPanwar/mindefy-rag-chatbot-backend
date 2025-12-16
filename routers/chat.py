from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from datetime import datetime
from bson import ObjectId

from dependencies.auth import require_approved_user
from breathe_Ai import breathe_chain
from db.mongo import get_database
from schemas.chat import (
    ChatCreateRequest,
    ChatUpdateRequest,
    ChatResponse as ChatHistoryResponse,
    ChatHistoryListItem,
    ChatHistoryDetail,
    DeleteResponse,
    MessageResponse
)

# rag imports
from core.config import settings
from rag_services.llm import LLMService
from models.rag_model import ChatRequest, ChatResponse as RagChatResponse
from rag_services.state import global_state

router = APIRouter()

llm_service = LLMService(settings.CHAT_MODEL, settings.TEMPERATURE, settings.MAX_TOKENS)

def generate_title_from_message(message: str, max_length: int = 50) -> str:
    """Generate a chat title from the first user message"""
    if len(message) <= max_length:
        return message
    return message[:max_length].rsplit(' ', 1)[0] + "..."

@router.post("/chat", response_model=ChatHistoryResponse)
async def create_or_continue_chat(
    payload: ChatCreateRequest,
    current_user: dict = Depends(require_approved_user),
    chat_id: Optional[str] = Query(None, description="Chat ID to continue existing conversation")
):
    """
    Create new chat or continue existing chat.
    
    - If chat_id is provided: Add message to existing chat
    - If chat_id is None: Create new chat
    
    Request body:
    ```json
    {
        "user_input": "Your message here"
    }
    ```
    
    Response:
    ```json
    {
        "chat_id": "507f1f77bcf86cd799439011",
        "response": "AI response here",
        "title": "Chat title"
    }
    ```
    """
    user_input = payload.user_input
    
    if not user_input or not isinstance(user_input, str):
        raise HTTPException(
            status_code=400,
            detail="'user_input' is required and must be a string"
        )
    
    db = get_database()
    chat_collection = db["chat_histories"]
    user_id = str(current_user["_id"])
    
    try:
        # Get or create chat
        if chat_id:
            # Validate ObjectId format
            if not ObjectId.is_valid(chat_id):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid chat_id format"
                )
            
            # Validate chat exists and belongs to user
            chat = await chat_collection.find_one({
                "_id": ObjectId(chat_id),
                "user_id": user_id,
                "is_deleted": False
            })
            
            if not chat:
                raise HTTPException(
                    status_code=404,
                    detail="Chat not found or you don't have access"
                )
            
            # Load conversation history into memory
            chain = breathe_chain()
            for msg in chat.get("messages", []):
                if msg["role"] == "user":
                    chain.memory.chat_memory.add_user_message(msg["content"])
                else:
                    chain.memory.chat_memory.add_ai_message(msg["content"])
        else:
            # Create new chat
            chain = breathe_chain()
            title = generate_title_from_message(user_input)
            
            new_chat = {
                "user_id": user_id,
                "title": title,
                "messages": [],
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "is_deleted": False
            }
            
            result = await chat_collection.insert_one(new_chat)
            chat_id = str(result.inserted_id)
            chat = new_chat
            chat["_id"] = result.inserted_id
        
        # Get AI response
        result = chain.invoke({"input": user_input})
        response_text = result.get("response", str(result))
        
        # Save messages to database
        user_message = {
            "role": "user",
            "content": user_input,
            "timestamp": datetime.utcnow()
        }
        
        assistant_message = {
            "role": "assistant",
            "content": response_text,
            "timestamp": datetime.utcnow()
        }
        
        await chat_collection.update_one(
            {"_id": ObjectId(chat_id)},
            {
                "$push": {
                    "messages": {
                        "$each": [user_message, assistant_message]
                    }
                },
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        
        return ChatHistoryResponse(
            chat_id=chat_id,
            response=response_text,
            title=chat.get("title", "New Chat")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chats", response_model=List[ChatHistoryListItem])
async def get_chat_history_list(
    current_user: dict = Depends(require_approved_user),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return")
):
    """
    Get list of all chat histories for the current user.
    
    Returns list of chats sorted by most recently updated first.
    
    Query parameters:
    - skip: Number of records to skip (default: 0)
    - limit: Maximum records to return (default: 50, max: 100)
    
    Response:
    ```json
    [
        {
            "_id": "507f1f77bcf86cd799439011",
            "title": "Chat about mindfulness",
            "created_at": "2025-10-23T10:44:00Z",
            "updated_at": "2025-10-23T11:00:00Z",
            "message_count": 10
        }
    ]
    ```
    """
    db = get_database()
    chat_collection = db["chat_histories"]
    user_id = str(current_user["_id"])
    
    try:
        # Query with pagination
        cursor = chat_collection.find(
            {"user_id": user_id, "is_deleted": False}
        ).sort("updated_at", -1).skip(skip).limit(limit)
        
        chats = await cursor.to_list(length=limit)
        
        # Format response
        chat_list = []
        for chat in chats:
            chat_list.append({
                "_id": str(chat["_id"]),
                "title": chat.get("title", "Untitled Chat"),
                "created_at": chat["created_at"],
                "updated_at": chat["updated_at"],
                "message_count": len(chat.get("messages", []))
            })
        
        return chat_list
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/chats/{chat_id}", response_model=ChatHistoryDetail)
async def get_chat_by_id(
    chat_id: str,
    current_user: dict = Depends(require_approved_user)
):
    """
    Get complete chat history by ID.
    
    Returns full chat with all messages in chronological order.
    
    Response:
    ```json
    {
        "_id": "507f1f77bcf86cd799439011",
        "user_id": "507f191e810c19729de860ea",
        "title": "Chat about mindfulness",
        "messages": [
            {
                "role": "user",
                "content": "Tell me about mindfulness",
                "timestamp": "2025-10-23T10:44:00Z"
            },
            {
                "role": "assistant",
                "content": "Mindfulness is...",
                "timestamp": "2025-10-23T10:44:05Z"
            }
        ],
        "created_at": "2025-10-23T10:44:00Z",
        "updated_at": "2025-10-23T11:00:00Z"
    }
    ```
    """
    db = get_database()
    chat_collection = db["chat_histories"]
    user_id = str(current_user["_id"])
    
    # Validate ObjectId format
    if not ObjectId.is_valid(chat_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid chat_id format"
        )
    
    try:
        chat = await chat_collection.find_one({
            "_id": ObjectId(chat_id),
            "user_id": user_id,
            "is_deleted": False
        })
        
        if not chat:
            raise HTTPException(
                status_code=404,
                detail="Chat not found or you don't have access"
            )
        
        # Format response
        messages = [
            MessageResponse(
                role=msg["role"],
                content=msg["content"],
                timestamp=msg["timestamp"]
            )
            for msg in chat.get("messages", [])
        ]
        
        return ChatHistoryDetail(
            _id=str(chat["_id"]),
            user_id=chat["user_id"],
            title=chat.get("title", "Untitled Chat"),
            messages=messages,
            created_at=chat["created_at"],
            updated_at=chat["updated_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/chats/{chat_id}", response_model=ChatHistoryDetail)
async def rename_chat(
    chat_id: str,
    payload: ChatUpdateRequest,
    current_user: dict = Depends(require_approved_user)
):
    """
    Rename chat history.
    
    Request body:
    ```json
    {
        "title": "New Chat Title"
    }
    ```
    
    Returns the updated chat details.
    """
    db = get_database()
    chat_collection = db["chat_histories"]
    user_id = str(current_user["_id"])
    
    if not payload.title or len(payload.title.strip()) == 0:
        raise HTTPException(
            status_code=400,
            detail="Title cannot be empty"
        )
    
    # Validate ObjectId format
    if not ObjectId.is_valid(chat_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid chat_id format"
        )
    
    try:
        # Update chat title
        result = await chat_collection.find_one_and_update(
            {
                "_id": ObjectId(chat_id),
                "user_id": user_id,
                "is_deleted": False
            },
            {
                "$set": {
                    "title": payload.title.strip(),
                    "updated_at": datetime.utcnow()
                }
            },
            return_document=True
        )
        
        if not result:
            raise HTTPException(
                status_code=404,
                detail="Chat not found or you don't have access"
            )
        
        # Format response
        messages = [
            MessageResponse(
                role=msg["role"],
                content=msg["content"],
                timestamp=msg["timestamp"]
            )
            for msg in result.get("messages", [])
        ]
        
        return ChatHistoryDetail(
            _id=str(result["_id"]),
            user_id=result["user_id"],
            title=result["title"],
            messages=messages,
            created_at=result["created_at"],
            updated_at=result["updated_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/chats/{chat_id}", response_model=DeleteResponse)
async def delete_chat(
    chat_id: str,
    current_user: dict = Depends(require_approved_user),
    permanent: bool = Query(False, description="Permanently delete chat (cannot be recovered)")
):
    """
    Delete chat history.
    
    - Default: Soft delete (is_deleted = True) - can be recovered
    - With permanent=true query param: Hard delete from database - cannot be recovered
    
    Query parameters:
    - permanent: Set to true for permanent deletion (default: false)
    
    Response:
    ```json
    {
        "success": true,
        "message": "Chat deleted successfully"
    }
    ```
    """
    db = get_database()
    chat_collection = db["chat_histories"]
    user_id = str(current_user["_id"])
    
    # Validate ObjectId format
    if not ObjectId.is_valid(chat_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid chat_id format"
        )
    
    try:
        if permanent:
            # Hard delete - permanently remove from database
            result = await chat_collection.delete_one({
                "_id": ObjectId(chat_id),
                "user_id": user_id
            })
            
            if result.deleted_count == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Chat not found or you don't have access"
                )
            
            return DeleteResponse(
                success=True,
                message="Chat permanently deleted"
            )
        else:
            # Soft delete - mark as deleted but keep in database
            result = await chat_collection.update_one(
                {
                    "_id": ObjectId(chat_id),
                    "user_id": user_id,
                    "is_deleted": False
                },
                {
                    "$set": {
                        "is_deleted": True,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            if result.matched_count == 0:
                raise HTTPException(
                    status_code=404,
                    detail="Chat not found or you don't have access"
                )
            
            return DeleteResponse(
                success=True,
                message="Chat deleted successfully"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

# Rag chat bot API integration
@router.post("/rag-chat", response_model=RagChatResponse)
async def chat(request: ChatRequest):
    """Chat with the uploaded document."""
    
    if global_state['retriever'] is None:
        raise HTTPException(
            status_code=404,
            detail="No document uploaded. Please upload a PDF first."
        )
    
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    try:
        # Search for relevant chunks
        results = global_state['retriever'].search(request.message, settings.TOP_K_RESULTS)
        
        # Combine context
        context = "\n\n".join([chunk for chunk, _ in results])
        
        # Generate answer
        answer = llm_service.generate_answer(
            request.message,
            context,
            global_state['history']
        )
        
        # Update history (limit to max pairs)
        global_state['history'].append({
            'user': request.message,
            'assistant': answer
        })
        
        # Keep only last MAX_HISTORY_PAIRS
        if len(global_state['history']) > settings.MAX_HISTORY_PAIRS:
            global_state['history'] = global_state['history'][-settings.MAX_HISTORY_PAIRS:]
        
        # Prepare sources
        sources = [
            chunk[:150] + "..." if len(chunk) > 150 else chunk
            for chunk, _ in results
        ]
        
        return RagChatResponse(
            answer=answer,
            sources=sources
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating response: {str(e)}"
        )
