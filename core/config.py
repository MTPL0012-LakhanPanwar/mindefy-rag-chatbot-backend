from pydantic_settings import BaseSettings
from pydantic import AnyUrl, Field
from typing import List, Optional


class Settings(BaseSettings):
    app_name: str = "Mindefy AI Backend"
    environment: str = Field(default="development")
    Version: str = "1.0.0"
    

    # Mongo (database name is extracted from the URI path)
    mongo_uri: AnyUrl | str = Field(default="")

    # JWT
    jwt_secret_key: str = Field(default="change-this-secret")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=21600)
    refresh_token_expire_days: int = Field(default=15)

    # CORS
    cors_allow_origins: List[str] = Field(default_factory=lambda: ["*"])

    # Social providers
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    google_redirect_uri: Optional[str] = None
    frontend_url: Optional[str] = None
    frontend_chat_route: Optional[str] = None

    # Email settings
    mail_username: Optional[str] = None
    mail_password: Optional[str] = None
    mail_from: Optional[str] = None
    mail_from_name: str = "Mindefy AI"
    mail_port: int = 587
    mail_server: str = "smtp.gmail.com"
    mail_starttls: bool = True
    mail_ssl_tls: bool = False
    use_credentials: bool = True
    validate_certs: bool = True

    # File Upload Settings
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: List[str] = [".pdf"]
    
    # RAG Settings
    CHUNK_SIZE: int = 500
    CHUNK_OVERLAP: int = 100
    TOP_K_RESULTS: int = 3
    MAX_HISTORY_PAIRS: int = 5
    
    # OpenAI Settings
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    CHAT_MODEL: str = "gpt-4o-mini"
    TEMPERATURE: float = 0.3
    MAX_TOKENS: int = 500

    # TMDB Configuration
    # IMPORTANT: Set TMDB_API_KEY in .env file or as environment variable
    # Pydantic Settings will automatically read from .env file or environment variables
    # DO NOT commit your actual API key to version control
    # If not set, defaults to empty string (API calls will fail - set it in .env file)
    TMDB_API_KEY: str = ""
    POSTER_BASE_URL: str = "https://image.tmdb.org/t/p/w500"
   
    
    # CORS Configuration
    BACKEND_CORS_ORIGINS: list = ["*"]
    
    # Cache Configuration
    CACHE_TTL: int = 3600  # 1 hour in seconds
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 10
    MAX_PAGE_SIZE: int = 100
    


    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
        "extra": "ignore",
    }


settings = Settings()