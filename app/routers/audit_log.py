from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    action: Optional[str] = None,
    key_id: Optional[int] = None,
    page: int = 1,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    limit = 20
    offset = (page - 1) * limit

    # Query logs belonging to user
    query = db.query(AuditLog).filter(AuditLog.user_id == user.id)
    
    if action:
        query = query.filter(AuditLog.action == action)
    if key_id:
        query = query.filter(AuditLog.api_key_id == key_id)

    total_logs = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    # Retrieve all user's keys to populate filter options
    keys = db.query(APIKey).filter(APIKey.user_id == user.id).all()
    
    total_pages = (total_logs + limit - 1) // limit if total_logs > 0 else 1

    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "user": user,
            "logs": logs,
            "keys": keys,
            "current_action": action or "",
            "current_key_id": key_id or "",
            "page": page,
            "total_pages": total_pages
        }
    )
