"""
Configuration settings for MindfulNest API.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Simple configuration class."""

    # API Settings
    API_TITLE: Final[str] = "MindfulNest API"
    API_VERSION: Final[str] = "1.0.0"

    # OpenAI Settings
    OPENAI_API_KEY: Final[str | None] = os.getenv("OPENAI_API_KEY")
    EMBEDDING_MODEL: Final[str] = "text-embedding-3-small"
    LLM_MODEL: Final[str] = "gpt-4o-mini"
    LLM_TEMPERATURE: Final[float] = 0.0
    LLM_MAX_TOKENS: Final[int] = 500

    # RAG Settings
    RETRIEVAL_K: Final[int] = 5  # Number of documents to retrieve
    CHUNK_SIZE: Final[int] = 800
    CHUNK_OVERLAP: Final[int] = 150
    MAX_CHAT_HISTORY: Final[int] = 5  # Maximum conversation pairs to keep

    # Vector Store Settings
    INDEX_PATH: Final[Path] = Path("faiss_index")
    INDEX_FILE: Final[Path] = INDEX_PATH / "index.faiss"

    # Logging
    LOG_LEVEL: Final[str] = "INFO"  # DEBUG, INFO, WARNING, ERROR

    # Flask Settings
    FLASK_HOST: Final[str] = "0.0.0.0"
    FLASK_PORT: Final[int] = 5000
    FLASK_DEBUG: Final[bool] = False

    @classmethod
    def validate(cls) -> None:
        """Check if required configurations are set."""
        if not cls.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY environment variable is not set. "
                "Please create a .env file with OPENAI_API_KEY=your-key",
            )
        # Don't fail if index doesn't exist - we'll create it
