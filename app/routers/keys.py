import hashlib
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from typing import Optional
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import encrypt_key_value, decrypt_key_value, verify_password
from app.models.user import User
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.api_key_usage import APIKeyUsage
from app.services.leak_scanner import scan_key_for_leaks

from app.services.plan_detector import detect_billing_plan

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def log_audit(db: Session, user_id: int, api_key_id: Optional[int], action: str):
    log_entry = AuditLog(user_id=user_id, api_key_id=api_key_id, action=action)
    db.add(log_entry)
    db.commit()

def extract_prefix(value: str, service: str) -> str:
    val = value.strip()
    service_lower = service.lower()
    if "openai" in service_lower and val.startswith("sk-proj-"):
        return val[:16]  # sk-proj- + 8 chars
    elif val.startswith("sk-"):
        return val[:11]  # sk- + 8 chars
    elif val.startswith("AKIA"):
        return val[:12]  # AWS format
    else:
        # Generic prefix extraction: keep first 8-10 chars
        return val[:max(6, min(10, len(val)))]

@router.get("/keys", response_class=HTMLResponse)
def keys_page(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Retrieve user's API keys ordered by creation date
    keys = db.query(APIKey).filter(APIKey.user_id == user.id).order_by(APIKey.created_at.desc()).all()
    return templates.TemplateResponse(request=request, name="keys.html", context={"user": user, "keys": keys})

@router.post("/keys")
def create_key(
    request: Request,
    label: str = Form(...),
    service: str = Form(...),
    value: str = Form(...),
    expires_at_str: Optional[str] = Form(None, alias="expires_at"),
    billing_plan: str = Form("auto"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    label = label.strip()
    service = service.strip()
    value = value.strip()
    billing_plan = billing_plan.strip().lower()
    if billing_plan not in ["free", "paid", "auto"]:
        billing_plan = "free"
    
    if billing_plan == "auto":
        billing_plan = detect_billing_plan(service, value)
    
    if not label or not service or not value:
        return JSONResponse(status_code=400, content={"error": "All fields are required."})

    # Validate expires_at
    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "Invalid date format for expiration."})

    # Fingerprint key to detect duplicates
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()
    duplicate = db.query(APIKey).filter(APIKey.user_id == user.id, APIKey.key_fingerprint == fingerprint).first()
    if duplicate:
        return JSONResponse(status_code=400, content={"error": "This API key has already been stored."})

    # Encrypt and store key prefix
    prefix = extract_prefix(value, service)
    encrypted = encrypt_key_value(value)

    new_key = APIKey(
        user_id=user.id,
        label=label,
        service=service,
        key_fingerprint=fingerprint,
        key_prefix=prefix,
        encrypted_value=encrypted,
        expires_at=expires_at,
        status="active",
        billing_plan=billing_plan
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    # Log action
    log_audit(db, user.id, new_key.id, "created")

    return JSONResponse({
        "status": "success",
        "message": "API key successfully stored in vault.",
        "key": {
            "id": new_key.id,
            "label": new_key.label,
            "service": new_key.service,
            "prefix": new_key.key_prefix,
            "status": new_key.status,
            "billing_plan": new_key.billing_plan,
            "created_at": new_key.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
    })

@router.post("/keys/{key_id}/reveal")
def reveal_key(
    key_id: int,
    password: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Verify user's password for security re-auth
    if not verify_password(password, user.password_hash):
        return JSONResponse(status_code=400, content={"error": "Incorrect password. Access denied."})

    try:
        # Decrypt secret
        decrypted = decrypt_key_value(key.encrypted_value)
        # Log reveal event
        log_audit(db, user.id, key.id, "viewed")
        return JSONResponse({"status": "success", "value": decrypted})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to decrypt key: {str(e)}"})

@router.post("/keys/{key_id}/update")
def update_key(
    key_id: int,
    label: str = Form(...),
    service: str = Form(...),
    expires_at_str: Optional[str] = Form(None, alias="expires_at"),
    billing_plan: str = Form("auto"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        return JSONResponse(status_code=404, content={"error": "API key not found."})

    label = label.strip()
    service = service.strip()
    billing_plan = billing_plan.strip().lower()
    if billing_plan not in ["free", "paid", "auto"]:
        billing_plan = "free"

    if billing_plan == "auto":
        try:
            raw_val = decrypt_key_value(key.encrypted_value)
            billing_plan = detect_billing_plan(service, raw_val)
        except Exception:
            billing_plan = "free"

    if not label or not service:
        return JSONResponse(status_code=400, content={"error": "Label and service are required."})

    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "Invalid date format."})

    key.label = label
    key.service = service
    key.expires_at = expires_at
    key.billing_plan = billing_plan
    key.last_rotated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    log_audit(db, user.id, key.id, "rotated")

    return JSONResponse({"status": "success", "message": "API key metadata updated successfully."})

@router.post("/keys/{key_id}/revoke")
def revoke_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        return JSONResponse(status_code=404, content={"error": "API key not found."})

    key.status = "revoked"
    db.commit()

    log_audit(db, user.id, key.id, "revoked")

    return JSONResponse({"status": "success", "message": "API key status set to revoked."})

@router.delete("/keys/{key_id}")
def delete_key(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        return JSONResponse(status_code=404, content={"error": "API key not found."})

    # Log audit trail before deleting key (the foreign key will set to NULL)
    log_audit(db, user.id, key.id, "deleted")

    db.delete(key)
    db.commit()

    return JSONResponse({"status": "success", "message": "API key permanently deleted."})

@router.post("/keys/{key_id}/scan-now")
def scan_now(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        return JSONResponse(status_code=404, content={"error": "API key not found."})

    if key.status == "revoked":
        return JSONResponse(status_code=400, content={"error": "Cannot scan a revoked key."})

    # Trigger scan
    leaked = scan_key_for_leaks(db, key)

    return JSONResponse({
        "status": "success",
        "leaked": leaked,
        "message": "Manual scan completed. API key is secure." if not leaked else "API Key has been flagged as leaked!"
    })

class UsageReport(BaseModel):
    tokens_used: int
    request_count: int = 1

@router.get("/keys/{key_id}/analytics", response_class=HTMLResponse)
def key_analytics_page(
    key_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Aggregate stats for this key
    total_tokens = db.query(func.sum(APIKeyUsage.tokens_used)).filter(APIKeyUsage.api_key_id == key.id).scalar() or 0
    total_requests = db.query(func.sum(APIKeyUsage.request_count)).filter(APIKeyUsage.api_key_id == key.id).scalar() or 0

    # Calculate Average Tokens per Request for this key
    avg_tokens_per_req = int(total_tokens / total_requests) if total_requests > 0 else 0

    # Calculate Estimated Cost for this key (USD to INR conversion)
    service_lower = key.service.lower()
    if "openai" in service_lower:
        cost_usd = (total_tokens / 1000.0) * 0.002
    elif "google" in service_lower or "gemini" in service_lower:
        cost_usd = (total_tokens / 1000.0) * 0.00015
    else:
        cost_usd = (total_tokens / 1000.0) * 0.001

    USD_TO_INR = 83.50
    estimated_cost_inr = cost_usd * USD_TO_INR

    # Recent Audit Logs for this key
    logs = db.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.api_key_id == key.id
    ).order_by(AuditLog.timestamp.desc()).limit(10).all()

    return templates.TemplateResponse(
        request=request,
        name="key_analytics.html",
        context={
            "user": user,
            "key": key,
            "total_tokens": f"{total_tokens:,}",
            "total_requests": f"{total_requests:,}",
            "avg_tokens_per_req": f"{avg_tokens_per_req:,}",
            "estimated_cost": f"₹{estimated_cost_inr:,.2f}" if estimated_cost_inr >= 0.01 else f"₹{estimated_cost_inr:,.4f}",
            "logs": logs
        }
    )

@router.get("/keys/{key_id}/chart-data")
def key_chart_data(
    key_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user.id).first()
    if not key:
        return JSONResponse(status_code=404, content={"error": "Key not found"})

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    seven_days_ago = now - timedelta(days=7)

    # Daily token usage (last 7 days)
    usage = db.query(
        func.date(APIKeyUsage.timestamp).label("day"),
        func.sum(APIKeyUsage.tokens_used).label("tokens"),
        func.sum(APIKeyUsage.request_count).label("requests")
    ).filter(
        APIKeyUsage.api_key_id == key.id,
        APIKeyUsage.timestamp >= seven_days_ago
    ).group_by(func.date(APIKeyUsage.timestamp))\
     .order_by(func.date(APIKeyUsage.timestamp)).all()

    timeline_dict = {}
    requests_dict = {}
    for i in range(7):
        day = (now - timedelta(days=6 - i)).strftime("%Y-%m-%d")
        timeline_dict[day] = 0
        requests_dict[day] = 0

    for day_val, tokens_cnt, requests_cnt in usage:
        day_str = str(day_val)
        if day_str in timeline_dict:
            timeline_dict[day_str] = int(tokens_cnt or 0)
            requests_dict[day_str] = int(requests_cnt or 0)

    return JSONResponse({
        "labels": list(timeline_dict.keys()),
        "tokens": list(timeline_dict.values()),
        "requests": list(requests_dict.values())
    })

@router.post("/keys/{key_id}/usage")
def report_usage(
    key_id: int,
    report: UsageReport,
    db: Session = Depends(get_db)
):
    # Public usage reporting endpoint for external client scripts.
    # Verification is based on key_id matching a valid stored vault key.
    key = db.query(APIKey).filter(APIKey.id == key_id).first()
    if not key:
        return JSONResponse(status_code=404, content={"error": "Key not found."})

    usage_entry = APIKeyUsage(
        api_key_id=key.id,
        tokens_used=report.tokens_used,
        request_count=report.request_count
    )
    db.add(usage_entry)
    db.commit()
    return {"status": "success", "message": "API usage registered successfully."}
