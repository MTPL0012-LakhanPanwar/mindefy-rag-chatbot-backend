from datetime import date
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
import httpx

from core.config import settings
from core.security import verify_password, hash_password, create_access_token, create_refresh_token
from dependencies.auth import get_current_user
from schemas.auth import (
    SignupRequest, TokenPair, TokenRefreshRequest, 
    SocialLoginRequest, ChangePasswordRequest
)
from schemas.user import UserOut
from services import users as user_service
# from services.email import email_service


router = APIRouter()


@router.post("/signup", response_model=UserOut, status_code=201)
async def signup(payload: SignupRequest):
    existing = await user_service.find_by_email_or_username(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    existing = await user_service.find_by_email_or_username(payload.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed = hash_password(payload.password)
    doc = await user_service.create_user({
        "username": payload.username,
        "email": payload.email,
        "hashed_password": hashed,
        "dob": payload.dob,
        "gender": payload.gender,
        "userType": "user",
        "isActive": True,
        "isApproved": "pending",  # requires admin approval
        "provider": "credentials",
    })
    
    # Send notification to admin about new user signup
    # try:
    #     await email_service.send_user_signup_notification(doc)
    # except Exception as e:
    #     print(f"Failed to send signup notification: {e}")
    
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


@router.post("/login", response_model=TokenPair)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await user_service.find_by_email_or_username(form_data.username)
    if not user or not user.get("hashed_password"):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="User is deactivated")

    access = create_access_token(str(user["_id"]), {"role": user.get("userType", "user")})
    refresh = create_refresh_token(str(user["_id"]))
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(payload: TokenRefreshRequest):
    try:
        decoded = jwt.decode(payload.refresh_token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        user_id = decoded.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="User is deactivated")
    access = create_access_token(str(user["_id"]), {"role": user.get("userType", "user")})
    refresh = create_refresh_token(str(user["_id"]))
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post("/change-password", status_code=200)
async def change_password(
    payload: ChangePasswordRequest,
    current_user = Depends(get_current_user)
):
    """
    Change password for the current logged-in user.
    Requires current password verification.
    """
    # Check if user uses social login (no password)
    if current_user.get("provider") != "credentials":
        raise HTTPException(
            status_code=400,
            detail="Cannot change password for social login accounts"
        )
    
    # Verify current password
    if not current_user.get("hashed_password"):
        raise HTTPException(
            status_code=400,
            detail="User has no password set"
        )
    
    if not verify_password(payload.current_password, current_user["hashed_password"]):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )
    
    # Validate new password is different from current
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different from current password"
        )
    
    # Validate password strength
    if len(payload.new_password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )
    
    # Hash and update password
    hashed_password = hash_password(payload.new_password)
    
    try:
        await user_service.update_user_password(
            str(current_user["_id"]), 
            hashed_password
        )
    except Exception as e:
        print(f"Failed to update password: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to change password. Please try again later."
        )    
   
    return {
        "message": "Password changed successfully",
        "success": True
    }


@router.delete("/delete-account", status_code=200)
async def delete_account(current_user = Depends(get_current_user)):
    """
    Delete the current logged-in user's account.
    This action is irreversible.
    """
    user_id = str(current_user["_id"])
    
    # Check if user is admin (optional protection)
    if current_user.get("userType") == "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin accounts cannot be deleted through this endpoint"
        )
    
    try:
        # Delete user from database
        deleted = await user_service.delete_user(user_id)
        
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail="User not found or already deleted"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Failed to delete user account: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to delete account. Please try again later."
        )
   
    return {
        "message": "Account deleted successfully",
        "success": True
    }

@router.post("/social-login", response_model=TokenPair)
async def social_login(payload: SocialLoginRequest):
    user = None
    provider = payload.provider.lower()

    if provider == "google":
        if not payload.id_token:
            raise HTTPException(status_code=400, detail="id_token required for Google")

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": payload.id_token}
            )

        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google token")

        data = resp.json()
        if settings.google_client_id and data.get("aud") != settings.google_client_id:
            raise HTTPException(status_code=401, detail="Invalid Google client")

        profile = {
            "email": data.get("email"),
            "username": data.get("email", "user").split("@")[0]
        }

        user = await user_service.upsert_social_user("google", data.get("sub"), profile)

    elif provider == "facebook":
        if not payload.access_token:
            raise HTTPException(status_code=400, detail="access_token required for Facebook")

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://graph.facebook.com/me",
                params={"fields": "id,name,email", "access_token": payload.access_token},
            )

        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Facebook token")

        data = resp.json()
        email = data.get("email") or f"fb_{data.get('id')}@facebook.local"
        profile = {"email": email, "username": email.split("@")[0]}
        user = await user_service.upsert_social_user("facebook", data.get("id"), profile)

    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # Safety check
    if not user:
        raise HTTPException(status_code=500, detail="User could not be created or fetched")

    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="User is deactivated")

    access = create_access_token(str(user["_id"]), {"role": user.get("userType", "user")})
    refresh = create_refresh_token(str(user["_id"]))

    # return tokens + full user info
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "user": {
            "id": str(user["_id"]),
            "username": user.get("username"),
            "email": user.get("email"),
            "gender": user.get("gender"),
            "dob": user.get("dob"),
            "userType": user.get("userType", "user"),
            "isActive": user.get("isActive", True),
            "isApproved": user.get("isApproved", "pending"),
        }
    }