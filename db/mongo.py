from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
import certifi

from core.config import settings

# Global connection variables
mongo_client: Optional[AsyncIOMotorClient] = None
db: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo() -> None:
    """
    Initialize MongoDB connection using Motor and verify SSL certificates.
    Creates indexes for chat_histories collection for better performance.
    """
    global mongo_client, db
    if mongo_client is None:
        mongo_client = AsyncIOMotorClient(
            str(settings.mongo_uri),
            tlsCAFile=certifi.where()  # Required for MongoDB Atlas SSL connections
        )
        # Get database from the URI path (e.g., /rag-chatbot in the connection string)
        db = mongo_client.get_default_database()
        
        # Create indexes for chat_histories collection
        await create_chat_indexes()
        
        print(f"Connected to MongoDB: {db.name}")


async def close_mongo_connection() -> None:
    """
    Close the MongoDB connection.
    """
    global mongo_client, db
    if mongo_client is not None:
        mongo_client.close()
        mongo_client = None
        db = None
        print("MongoDB connection closed")


def get_database() -> AsyncIOMotorDatabase:
    """
    Get the database instance.
    Raises RuntimeError if database is not connected.
    
    Returns:
        AsyncIOMotorDatabase: The MongoDB database instance
    """
    if db is None:
        raise RuntimeError(
            "Database not connected. Call connect_to_mongo() first."
        )
    return db


async def create_chat_indexes() -> None:
    """
    Create indexes for chat_histories collection to improve query performance.
    This is called automatically during connect_to_mongo().
    """
    if db is None:
        return
    
    chat_collection = db["chat_histories"]
    
    # Index for getting user's chats sorted by updated_at
    await chat_collection.create_index(
        [("user_id", 1), ("updated_at", -1)],
        name="user_updated_idx"
    )
    
    # Index for filtering non-deleted chats
    await chat_collection.create_index(
        [("user_id", 1), ("is_deleted", 1)],
        name="user_deleted_idx"
    )
    
    # Compound index for efficient queries
    await chat_collection.create_index(
        [("user_id", 1), ("is_deleted", 1), ("updated_at", -1)],
        name="user_active_chats_idx"
    )
    
    print("Chat history indexes created successfully")


# Backward compatibility: Export commonly used variables
__all__ = [
    "mongo_client",
    "db",
    "connect_to_mongo",
    "close_mongo_connection",
    "get_database",
    "create_chat_indexes"
]