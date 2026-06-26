from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import decode_token
from app.core.config import settings
from app.models.user import User

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    user = None
    email = None
    token_refreshed = False

    if access_token:
        payload = decode_token(access_token, settings.JWT_SECRET)
        if payload and payload.get("type") == "access":
            email = payload.get("sub")
            user = db.query(User).filter(User.email == email).first()

    # If access token is missing, expired, or user not found, try refresh token
    if not user and refresh_token:
        payload = decode_token(refresh_token, settings.JWT_REFRESH_SECRET)
        if payload and payload.get("type") == "refresh":
            email = payload.get("sub")
            user = db.query(User).filter(User.email == email).first()
            if user:
                token_refreshed = True

    if not user:
        # Check if the request is an API request or expects JSON
        accept_header = request.headers.get("accept", "")
        path = request.url.path
        if "application/json" in accept_header or path.startswith("/auth/me") or path.startswith("/keys/") or path.startswith("/alerts/") or path.startswith("/api/"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        else:
            # HTML request: redirect to login
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                detail="Redirecting to login",
                headers={"Location": "/login"}
            )

    if token_refreshed:
        # Store email on the request state so the middleware can set cookie
        request.state.new_access_token_email = email

    return user
