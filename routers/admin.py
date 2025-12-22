import os
import gc
import traceback
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from fastapi.responses import FileResponse

from dependencies.auth import require_admin
from schemas.user import UserOut, AdminUpdateRequestStatus
from services import users as user_service
from services.email import email_service

# ===== RAG Imports =====
from rag_services.pdf_processor import PDFProcessor
from rag_services.embeddings import EmbeddingService
from core.config import settings
from models.rag_model import UploadResponse
from rag_services.retrieval import HybridRetriever
from rag_services.state import global_state

router = APIRouter()

# =========================
# RAG Services
# =========================
pdf_processor = PDFProcessor()
embedding_service = EmbeddingService(settings.EMBEDDING_MODEL)

UPLOAD_DIR = Path("uploaded_pdfs")
UPLOAD_DIR.mkdir(exist_ok=True)


def clear_global_state():
    """Clear all RAG-related memory and delete PDF."""
    if global_state['retriever'] is not None:
        if hasattr(global_state['retriever'], 'dense_index'):
            global_state['retriever'].dense_index.reset()

    if global_state['pdf_path'] and os.path.exists(global_state['pdf_path']):
        try:
            os.remove(global_state['pdf_path'])
        except Exception as e:
            print(f"Error deleting PDF: {e}")

    global_state['retriever'] = None
    global_state['chunks'] = None
    global_state['history'] = []
    global_state['pdf_path'] = None
    global_state['pdf_filename'] = None
    global_state['pdf_size'] = None
    gc.collect()


# =====================================================================
# ======================== EXISTING CODE (UNCHANGED) ===================
# =====================================================================

@router.get("/users", response_model=List[UserOut])
async def list_users(_: dict = Depends(require_admin)):
    docs = await user_service.list_users()
    return [
        {
            "id": str(doc["_id"]),
            "username": doc["username"],
            "email": doc["email"],
            "gender": doc.get("gender"),
            "dob": doc.get("dob"),
            "userType": doc.get("userType", "user"),
            "isActive": doc.get("isActive", True),
            "isApproved": doc.get("isApproved", "pending"),
            "createdAt": doc.get("createdAt"),
            "updatedAt": doc.get("updatedAt"),
        }
        for doc in docs
    ]


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(user_id: str, _: dict = Depends(require_admin)):
    doc = await user_service.get_user_by_id(user_id)
    if not doc:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(doc["_id"]),
        "username": doc["username"],
        "email": doc["email"],
        "gender": doc.get("gender"),
        "dob": doc.get("dob"),
        "userType": doc.get("userType", "user"),
        "isActive": doc.get("isActive", True),
        "isApproved": doc.get("isApproved", "pending"),
        "createdAt": doc.get("createdAt"),
        "updatedAt": doc.get("updatedAt"),
    }


@router.post("/users/{user_id}/approval", response_model=UserOut)
async def update_approval(user_id: str, payload: AdminUpdateRequestStatus, _: dict = Depends(require_admin)):
    # Get user data before updating for notifications
    user_before = await user_service.get_user_by_id(user_id)
    if not user_before:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if approval status is actually changing
    current_approved = user_before.get("isApproved", "pending")
    if current_approved == payload.isApproved:
        # No change needed, return current data
        return {
            "id": str(user_before["_id"]),
            "username": user_before["username"],
            "email": user_before["email"],
            "gender": user_before.get("gender"),
            "dob": user_before.get("dob"),
            "userType": user_before.get("userType", "user"),
            "isActive": user_before.get("isActive", True),
            "isApproved": user_before.get("isApproved", "pending"),
            "createdAt": user_before.get("createdAt"),
            "updatedAt": user_before.get("updatedAt"),
        }
    
    ok = await user_service.set_approval(user_id, payload.isApproved)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    
    doc = await user_service.get_user_by_id(user_id)
    
    # Send notification to user about approval/rejection
    try:
        if payload.isApproved.strip().lower() == "approved":
            # Send approval notification
            await email_service.send_approval_notification(doc, True)
            # Send welcome email
            await email_service.send_welcome_email(doc)
        else:
            # Send rejection notification
            await email_service.send_approval_notification(doc, False)
    except Exception as e:
        print(f"Failed to send approval notification: {e}")
    
    return {
        "id": str(doc["_id"]),
        "username": doc["username"],
        "email": doc["email"],
        "gender": doc.get("gender"),
        "dob": doc.get("dob"),
        "userType": doc.get("userType", "user"),
        "isActive": doc.get("isActive", True),
        "isApproved": doc.get("isApproved", "pending"),
        "createdAt": doc.get("createdAt"),
        "updatedAt": doc.get("updatedAt"),
    }


# =====================================================================
# ======================== NEW RAG APIs (INTEGRATED) ===================
# =====================================================================

@router.post("/upload", response_model=UploadResponse, dependencies=[Depends(require_admin)])
async def upload_pdf(file: UploadFile = File(...)):
    if not file.filename.endswith(tuple(settings.ALLOWED_EXTENSIONS)):
        raise HTTPException(status_code=400, detail="Invalid file type")

    pdf_bytes = await file.read()
    pdf_size = len(pdf_bytes)

    if pdf_size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size limit exceeded")

    try:
        # Store existing PDFs to delete after successful upload
        existing_pdfs = list(UPLOAD_DIR.glob("*.pdf"))
        
        pdf_path = UPLOAD_DIR / file.filename
        
        # If same filename exists, use a temp name first
        temp_path = None
        if pdf_path.exists():
            from datetime import datetime
            temp_path = UPLOAD_DIR / f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            with open(temp_path, "wb") as f:
                f.write(pdf_bytes)
        else:
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)
            temp_path = pdf_path

        text = pdf_processor.extract_text(pdf_bytes)
        if not text or len(text.strip()) < 100:
            os.remove(temp_path)
            raise HTTPException(status_code=400, detail="Insufficient text content")

        chunks = pdf_processor.create_chunks(
            text,
            settings.CHUNK_SIZE,
            settings.CHUNK_OVERLAP
        )

        previous_chunks = len(global_state['chunks']) if global_state['chunks'] else 0
        
        # Delete old PDFs only after successful processing
        for existing_pdf in existing_pdfs:
            if existing_pdf.resolve() != temp_path.resolve():
                try:
                    if existing_pdf.exists():
                        os.remove(existing_pdf)
                except Exception as e:
                    print(f"Error deleting existing PDF {existing_pdf}: {e}")
        
        if global_state['retriever']:
            global_state['retriever'] = None
            global_state['chunks'] = None
            global_state['history'] = []
            gc.collect()

        retriever = HybridRetriever(chunks, embedding_service)
        
        # Rename temp file to final name if needed
        if temp_path != pdf_path:
            if pdf_path.exists():
                os.remove(pdf_path)
            os.rename(temp_path, pdf_path)

        global_state.update({
            'retriever': retriever,
            'chunks': chunks,
            'history': [],
            'pdf_path': str(pdf_path),
            'pdf_filename': pdf_path.name,
            'pdf_size': pdf_size
        })

        return UploadResponse(
            message="PDF processed successfully",
            chunks_count=len(chunks),
            is_update=previous_chunks > 0,
            previous_chunks=previous_chunks or None,
            filename=pdf_path.name,
            file_size=pdf_size
        )

    except Exception as e:
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/clear", dependencies=[Depends(require_admin)])
async def clear_document():
    if global_state['retriever'] is None:
        raise HTTPException(status_code=404, detail="No document to clear")

    clear_global_state()
    return {"message": "Document and vectors cleared successfully"}


@router.get("/pdf", dependencies=[Depends(require_admin)])
async def get_pdf():
    if not global_state['pdf_path'] or not os.path.exists(global_state['pdf_path']):
        raise HTTPException(status_code=404, detail="No PDF available")

    return FileResponse(
        path=global_state['pdf_path'],
        media_type="application/pdf",
        filename=global_state['pdf_filename']
    )


@router.get("/pdf/info", dependencies=[Depends(require_admin)])
async def get_pdf_info():
    """
    Get details about the uploaded PDF including name, size, and preview URL.
    """
    if not UPLOAD_DIR.exists():
        raise HTTPException(status_code=404, detail="No PDF uploaded")
    
    pdf_files = list(UPLOAD_DIR.glob("*.pdf"))
    
    if not pdf_files:
        raise HTTPException(status_code=404, detail="No PDF uploaded")
    
    pdf_file = pdf_files[0]
    file_stat = pdf_file.stat()
    
    return {
        "name": pdf_file.name,
        "size": file_stat.st_size,
        "size_formatted": f"{file_stat.st_size / 1024:.2f} KB" if file_stat.st_size < 1024 * 1024 else f"{file_stat.st_size / (1024 * 1024):.2f} MB",
        "preview_url": "/admin/pdf/preview"
    }


@router.get("/pdf/preview", dependencies=[Depends(require_admin)])
async def preview_pdf():
    """
    Get the PDF file for preview/download.
    """
    pdf_files = list(UPLOAD_DIR.glob("*.pdf"))
    
    if not pdf_files:
        raise HTTPException(status_code=404, detail="No PDF found")
    
    pdf_path = pdf_files[0]
    
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name
    )
