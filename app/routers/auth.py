import time
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Dict, List, Optional
from datetime import timedelta
from email_validator import validate_email, EmailNotValidError

from app.core.database import get_db
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.email_service import send_welcome_email

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Simple In-Memory Rate Limiter for Login
# structure: {ip: [timestamp1, timestamp2, ...]}
login_attempts: Dict[str, List[float]] = {}

def check_login_rate_limit(ip: str):
    now = time.time()
    # Clean up old timestamps (older than 60 seconds)
    if ip in login_attempts:
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]
    else:
        login_attempts[ip] = []

    if len(login_attempts[ip]) >= settings.RATE_LIMIT_LOGIN_PER_MIN:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again after a minute."
        )

def record_login_attempt(ip: str):
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(time.time())

@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request, error: Optional[str] = None):
    # If already logged in, redirect to dashboard
    if request.cookies.get("access_token"):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(request=request, name="register.html", context={"error": error})

@router.post("/auth/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Email validation
    email = email.strip()
    try:
        email_info = validate_email(email, check_deliverability=False)
        email = email_info.normalized
    except EmailNotValidError:
        return templates.TemplateResponse(
            request=request,
            name="register.html", 
            context={"error": "Please enter a valid email address.", "name": name, "email": email}
        )

    # Validation
    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="register.html", 
            context={"error": "Passwords do not match.", "name": name, "email": email}
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html", 
            context={"error": "Password must be at least 8 characters.", "name": name, "email": email}
        )

    # Check duplicate email
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="register.html", 
            context={"error": "Email is already registered.", "name": name}
        )

    # Create user
    hashed = hash_password(password)
    new_user = User(name=name, email=email, password_hash=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Send Welcome Email
    send_welcome_email(new_user.email, new_user.name)

    # Redirect to login with success message
    response = RedirectResponse(url="/login?success=Account+created+successfully.+Please+log+in.", status_code=303)
    return response

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: Optional[str] = None, success: Optional[str] = None):
    # If already logged in, redirect to dashboard
    if request.cookies.get("access_token"):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": error, "success": success})

@router.post("/auth/login")
def login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    ip = request.client.host if request.client else "unknown"
    
    # Check rate limit
    try:
        check_login_rate_limit(ip)
    except HTTPException as e:
        return templates.TemplateResponse(request=request, name="login.html", context={"error": e.detail})

    # Email validation
    email = email.strip()
    try:
        email_info = validate_email(email, check_deliverability=False)
        email = email_info.normalized
    except EmailNotValidError:
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Please enter a valid email address."})

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        record_login_attempt(ip)
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})

    # Successful login, clear history
    if ip in login_attempts:
        login_attempts[ip] = []

    # Generate tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    # Redirect to dashboard
    redirect_response = RedirectResponse(url="/dashboard", status_code=303)
    
    # Set cookies
    redirect_response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )
    redirect_response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )
    
    return redirect_response

@router.post("/auth/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response

@router.post("/auth/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    payload = decode_token(refresh_token, settings.JWT_REFRESH_SECRET)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token(data={"sub": user.email})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False
    )
    return {"status": "success", "message": "Token refreshed"}
