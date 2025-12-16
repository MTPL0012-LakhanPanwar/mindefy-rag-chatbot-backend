from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

def create_app() -> FastAPI:
    application = FastAPI(
        title="Mindefy AI API",
        description="API for conversational AI with memory and auth",
        version="1.0.0",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # DB lifecycle
    from db.mongo import connect_to_mongo, close_mongo_connection

    @application.on_event("startup")
    async def startup_event():
        await connect_to_mongo()

    @application.on_event("shutdown")
    async def shutdown_event():
        await close_mongo_connection()

    # Routers are imported lazily to avoid circular deps during app creation
    from routers.auth import router as auth_router
    from routers.admin import router as admin_router
    from routers.chat import router as chat_router
    from routers.users import router as users_router

    application.include_router(auth_router, prefix="/auth", tags=["auth"])
    application.include_router(admin_router, prefix="/admin", tags=["admin"])
    application.include_router(chat_router, tags=["chat"])
    application.include_router(users_router, prefix="/users", tags=["users"])

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
