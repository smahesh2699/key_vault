import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.security import create_access_token
from app.services.scheduler import start_scheduler, stop_scheduler
from app.routers import auth, keys, dashboard, alerts, audit_log

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    logger.info("Initializing KeyVault application...")
    start_scheduler()
    yield
    # Shutdown logic
    logger.info("Shutting down KeyVault application...")
    stop_scheduler()

app = FastAPI(
    title="KeyVault — API Key Management & Leak Detection Platform",
    lifespan=lifespan
)

# Cookie Refresh Middleware
# If the authentication dependency detects that the access token was expired
# but a valid refresh token existed, it saves the user's email on request.state.
# This middleware interceptor writes the updated access_token cookie to the response.
@app.middleware("http")
async def refresh_cookie_middleware(request: Request, call_next):
    response = await call_next(request)
    if hasattr(request.state, "new_access_token_email"):
        email = request.state.new_access_token_email
        logger.info(f"Silently refreshing access token for {email}...")
        access_token = create_access_token(data={"sub": email})
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            samesite="lax",
            secure=False  # Set to True in production (HTTPS)
        )
    return response

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Register routers
app.include_router(auth.router)
app.include_router(keys.router)
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(audit_log.router)
