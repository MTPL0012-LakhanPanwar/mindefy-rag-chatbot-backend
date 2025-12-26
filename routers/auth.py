from datetime import date
from typing import Any, Dict
import secrets

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
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

# Store state tokens temporarily (in production, use Redis or similar)
state_store = {}


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
        "userType": "admin",
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
        "userType": doc.get("userType", "admin"),
        "isActive": doc.get("isActive", True),
        "isApproved": doc.get("isApproved", "pending"),
        "createdAt": doc.get("createdAt"),
        "updatedAt": doc.get("updatedAt"),
    }


@router.post("/login", response_model=TokenPair)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await user_service.find_by_email_or_username(form_data.username)
    if not user or not user.get("hashed_password"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="User is deactivated")

    access = create_access_token(str(user["_id"]), {"role": user.get("userType", "admin")})
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
    access = create_access_token(str(user["_id"]), {"role": user.get("userType", "admin")})
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

@router.get("/google")
async def google_login(request: Request):
    """
    Initiate Google OAuth2 flow.
    Redirects user to Google's consent screen.
    """
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth credentials not configured"
        )
    
    # Generate state token for CSRF protection
    state = secrets.token_urlsafe(32)
    state_store[state] = True
    
    # Build Google OAuth2 authorization URL
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={settings.google_client_id}&"
        f"redirect_uri={settings.google_redirect_uri}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        f"state={state}"
    )
    
    return RedirectResponse(url=google_auth_url)


@router.get("/google/callback")
async def google_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """
    Handle Google OAuth2 callback.
    Exchanges authorization code for tokens, creates/logs in user,
    and redirects to frontend with access and refresh tokens.
    """
    # Check for errors from Google
    if error:
        print(f"Google OAuth error from provider: {error}")
        error_url = f"{settings.frontend_url}/login?error={error}"
        return RedirectResponse(url=error_url)
    
    # Validate state token (CSRF protection)
    if not state or state not in state_store:
        print(f"Invalid state token. State: {state}, Store has: {list(state_store.keys())}")
        error_url = f"{settings.frontend_url}/login?error=invalid_state"
        return RedirectResponse(url=error_url)
    
    # Remove used state token
    state_store.pop(state, None)
    
    # Validate authorization code
    if not code:
        print("No authorization code received from Google")
        error_url = f"{settings.frontend_url}/login?error=no_code"
        return RedirectResponse(url=error_url)
    
    try:
        # Exchange authorization code for access token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": settings.google_redirect_uri,
                    "grant_type": "authorization_code"
                }
            )
        
        if token_response.status_code != 200:
            error_detail = token_response.text
            print(f"Token exchange failed. Status: {token_response.status_code}, Response: {error_detail}")
            error_url = f"{settings.frontend_url}/login?error=token_exchange_failed"
            return RedirectResponse(url=error_url)
        
        token_data = token_response.json()
        google_access_token = token_data.get("access_token")
        
        if not google_access_token:
            print(f"No access token in response: {token_data}")
            error_url = f"{settings.frontend_url}/login?error=no_access_token"
            return RedirectResponse(url=error_url)
        
        # Get user info from Google
        async with httpx.AsyncClient() as client:
            user_info_response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {google_access_token}"}
            )
        
        if user_info_response.status_code != 200:
            print(f"Failed to get user info. Status: {user_info_response.status_code}, Response: {user_info_response.text}")
            error_url = f"{settings.frontend_url}/login?error=failed_to_get_user_info"
            return RedirectResponse(url=error_url)
        
        user_info = user_info_response.json()
        
        # Extract user profile
        google_id = user_info.get("id")
        email = user_info.get("email")
        name = user_info.get("name")
        username = name if name else (email.split("@")[0] if email else f"user_{google_id}")
        
        profile = {
            "email": email,
            "username": username
        }
        
        # Create or get existing user
        user = await user_service.upsert_social_user("google", google_id, profile)
        
        if not user:
            print(f"Failed to create/get user for Google ID: {google_id}, email: {email}")
            error_url = f"{settings.frontend_url}/login?error=user_creation_failed"
            return RedirectResponse(url=error_url)
        
        # Check if user is active
        if not user.get("isActive", True):
            print(f"User {user.get('email')} is deactivated")
            error_url = f"{settings.frontend_url}/login?error=user_deactivated"
            return RedirectResponse(url=error_url)
        
        # Generate JWT tokens
        access_token = create_access_token(
            str(user["_id"]),
            {"role": user.get("userType", "admin")}
        )
        refresh_token = create_refresh_token(str(user["_id"]))
        
        # Redirect to frontend with tokens as query parameters
        redirect_url = (
            f"{settings.frontend_url}{settings.frontend_chat_route}?"
            f"access_token={access_token}&"
            f"refresh_token={refresh_token}"
        )
        
        return RedirectResponse(url=redirect_url)
    
    except Exception as e:
        import traceback
        print(f"Google OAuth error: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        error_url = f"{settings.frontend_url}/login?error=authentication_failed&message={str(e)}"
        return RedirectResponse(url=error_url)