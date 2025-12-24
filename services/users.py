from datetime import datetime, date
from typing import Optional, Dict, Any, List
from bson import ObjectId

import db.mongo as mongo

async def find_by_email_or_username(username_or_email: str) -> Optional[Dict[str, Any]]:
    return await mongo.db["users"].find_one({
        "$or": [
            {"email": username_or_email.lower()},
            {"username": username_or_email},
        ]
    })


async def find_by_provider(provider: str, provider_id: str) -> Optional[Dict[str, Any]]:
    return await mongo.db["users"].find_one({"provider": provider, "providerId": provider_id})


async def create_user(data: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.utcnow()
    dob_value = data.get("dob")
    if isinstance(dob_value, date) and not isinstance(dob_value, datetime):
        dob_value = datetime.combine(dob_value, datetime.min.time())

    doc = {
        "username": data["username"],
        "email": data["email"].lower(),
        "hashed_password": data.get("hashed_password"),
        "dob": dob_value,
        "gender": data.get("gender"),
        "userType": data.get("userType", "admin"),
        "isActive": data.get("isActive", True),
        "isApproved": data.get("isApproved", "pending"),
        "provider": data.get("provider", "credentials"),
        "providerId": data.get("providerId"),
        "createdAt": now,
        "updatedAt": now,
    }
    res = await mongo.db["users"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return doc


async def upsert_social_user(provider: str, provider_id: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.utcnow()
    existing = await find_by_provider(provider, provider_id)
    if existing:
        await mongo.db["users"].update_one({"_id": existing["_id"]}, {"$set": {"updatedAt": now, "isActive": True}})
        return await mongo.db["users"].find_one({"_id": existing["_id"]})
    doc = {
        "username": profile.get("username") or profile.get("email").split("@")[0],
        "email": profile.get("email").lower(),
        "gender": profile.get("gender"),
        "dob": profile.get("dob"),
        "userType": "admin",
        "isActive": True,
        "isApproved": "pending",
        "provider": provider,
        "providerId": provider_id,
        "createdAt": now,
        "updatedAt": now,
    }
    res = await mongo.db["users"].insert_one(doc)
    doc["_id"] = res.inserted_id
    doc["is_new_user"] = True  # Flag to indicate this is a new user
    return doc


async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return await mongo.db["users"].find_one({"_id": oid})


async def list_users(limit: int = 50, skip: int = 0) -> List[Dict[str, Any]]:
    cursor = mongo.db["users"].find({}).skip(skip).limit(limit).sort("createdAt", -1)
    return [doc async for doc in cursor]


async def set_approval(user_id: str, approved: str) -> bool:
    try:
        oid = ObjectId(user_id)
    except Exception:
        return False
    res = await mongo.db["users"].update_one({"_id": oid}, {"$set": {"isApproved": approved, "updatedAt": datetime.utcnow()}})
    return res.modified_count > 0


async def set_active(user_id: str, active: bool) -> bool:
    try:
        oid = ObjectId(user_id)
    except Exception:
        return False
    res = await mongo.db["users"].update_one({"_id": oid}, {"$set": {"isActive": active, "updatedAt": datetime.utcnow()}})
    return res.modified_count > 0


async def update_user(user_id: str, update_data: Dict[str, Any]) -> bool:
    """Update user data with the provided fields"""
    try:
        oid = ObjectId(user_id)
    except Exception:
        return False
    
    # Add updatedAt timestamp
    update_data["updatedAt"] = datetime.utcnow()
    
    res = await mongo.db["users"].update_one({"_id": oid}, {"$set": update_data})
    return res.modified_count > 0

async def update_user_password(user_id: str, hashed_password: str) -> bool:
    """
    Update user password
    
    Args:
        user_id: User ID
        hashed_password: Hashed password
        
    Returns:
        True if updated successfully, False otherwise
    """
    try:
        result = await mongo.db["users"].update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "hashed_password": hashed_password,
                    "updatedAt": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating password: {e}")
        return False


async def delete_user(user_id: str) -> bool:
    """
    Delete user account
    
    Args:
        user_id: User ID to delete
        
    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        result = await mongo.db["users"].delete_one({"_id": ObjectId(user_id)})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False

async def upsert_social_user(
    provider: str, 
    provider_id: str, 
    profile: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Create or update social login user
    
    Args:
        provider: Social provider (google, facebook)
        provider_id: Provider-specific user ID
        profile: User profile data
        
    Returns:
        User document
    """
    # Check if user exists with this provider
    existing = await mongo.db["users"].find_one({
        "provider": provider,
        "providerId": provider_id
    })
    
    if existing:
        # Update last login
        await mongo.db["users"].update_one(
            {"_id": existing["_id"]},
            {
                "$set": {
                    "updatedAt": datetime.utcnow(),
                    "lastLogin": datetime.utcnow()
                }
            }
        )
        return existing
    
    # Check if user exists with same email
    email_user = await mongo.db["users"].find_one({"email": profile.get("email")})
    
    if email_user:
        # Link social account to existing user
        await mongo.db["users"].update_one(
            {"_id": email_user["_id"]},
            {
                "$set": {
                    "provider": provider,
                    "providerId": provider_id,
                    "updatedAt": datetime.utcnow(),
                    "lastLogin": datetime.utcnow()
                }
            }
        )
        return await get_user_by_id(str(email_user["_id"]))
    
    # Create new user
    user_data = {
        "username": profile.get("username"),
        "email": profile.get("email"),
        "provider": provider,
        "providerId": provider_id,
        "userType": "user",
        "isActive": True,
        "isApproved": "pending",
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
        "lastLogin": datetime.utcnow()
    }
    
    result = await mongo.db["users"].insert_one(user_data)
    user_data["_id"] = result.inserted_id
    
    return user_data


async def update_user_profile(
    user_id: str, 
    update_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Update user profile
    
    Args:
        user_id: User ID
        update_data: Data to update
        
    Returns:
        Updated user document
    """
    try:
        update_data["updatedAt"] = datetime.utcnow()
        
        result = await mongo.db["users"].update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            return await get_user_by_id(user_id)
        
        return None
    except Exception as e:
        print(f"Error updating user profile: {e}")
        return None

async def get_admin_users() -> List[Dict[str, Any]]:
    """Get all admin users from the database"""
    cursor = mongo.db["users"].find({
        "userType": "admin",
        "isActive": True
    })
    return [doc async for doc in cursor]


async def get_admin_emails() -> List[str]:
    """Get list of admin email addresses"""
    admins = await get_admin_users()
    return [admin["email"] for admin in admins if admin.get("email")]


