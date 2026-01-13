"""
Configuration settings for MindfulNest API
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Simple configuration class"""

    # API Settings
    API_TITLE = "MindfulNest API"
    API_VERSION = "1.0.0"

    # OpenAI Settings
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    EMBEDDING_MODEL = "text-embedding-3-small"
    LLM_MODEL = "gpt-4o-mini"
    LLM_TEMPERATURE = 0.0
    LLM_MAX_TOKENS = 500

    # RAG Settings
    RETRIEVAL_K = 5  # Number of documents to retrieve
    CHUNK_SIZE = 800
    CHUNK_OVERLAP = 150
    MAX_CHAT_HISTORY = 5  # Maximum conversation pairs to keep

    # Vector Store Settings
    INDEX_PATH = Path("faiss_index")
    INDEX_FILE = INDEX_PATH / "index.faiss"

    # Logging
    LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

    # Flask Settings
    FLASK_HOST = "0.0.0.0"
    FLASK_PORT = 5000
    FLASK_DEBUG = False

    @classmethod
    def validate(cls):
        """Check if required configurations are set"""
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY environment variable is not set. Please create a .env file with OPENAI_API_KEY=your-key")

        # Don't fail if index doesn't exist - we'll create it
        return True
