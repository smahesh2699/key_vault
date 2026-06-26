from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.api_key import APIKey
from app.models.leak_alert import LeakAlert
from app.models.audit_log import AuditLog

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def log_audit(db: Session, user_id: int, api_key_id: Optional[int], action: str):
    log_entry = AuditLog(user_id=user_id, api_key_id=api_key_id, action=action)
    db.add(log_entry)
    db.commit()

@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Fetch alerts for the user's keys, ordered by detection date
    alerts = db.query(LeakAlert).join(APIKey).filter(
        APIKey.user_id == user.id
    ).order_by(LeakAlert.detected_at.desc()).all()
    
    return templates.TemplateResponse(request=request, name="alerts.html", context={"user": user, "alerts": alerts})

@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Find alert ensuring it belongs to the current user
    alert = db.query(LeakAlert).join(APIKey).filter(
        LeakAlert.id == alert_id,
        APIKey.user_id == user.id
    ).first()
    
    if not alert:
        return JSONResponse(status_code=404, content={"error": "Leak alert not found."})

    alert.resolved = True
    db.commit()

    # Check if there are other unresolved alerts for this key
    unresolved_count = db.query(LeakAlert).filter(
        LeakAlert.api_key_id == alert.api_key_id,
        LeakAlert.resolved == False
    ).count()

    # If all alerts resolved for this key, set status back to active (if it was leaked)
    key = db.query(APIKey).filter(APIKey.id == alert.api_key_id).first()
    if unresolved_count == 0 and key and key.status == "leaked":
        key.status = "active"
        db.commit()

    log_audit(db, user.id, alert.api_key_id, "resolved")

    return JSONResponse({"status": "success", "message": "Leak alert marked as resolved."})
