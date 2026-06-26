import httpx
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from typing import Optional

from app.core.config import settings
from app.models.api_key import APIKey
from app.models.leak_alert import LeakAlert
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

def log_audit(db: Session, user_id: int, api_key_id: Optional[int], action: str):
    log_entry = AuditLog(user_id=user_id, api_key_id=api_key_id, action=action)
    db.add(log_entry)
    db.commit()

def scan_key_for_leaks(db: Session, key: APIKey) -> bool:
    """
    Scans a key for leaks. Checks GitHub Code Search for the prefix.
    If the key's label contains 'TEST_LEAK', it triggers a mock leak detection.
    """
    logger.info(f"Scanning key {key.id} (prefix: {key.key_prefix}) for leaks...")
    leaked = False
    source_url = None
    
    # Check Simulation/Mock Mode
    if "test_leak" in key.label.lower():
        logger.info(f"Simulating leak detection for key {key.id} (TEST_LEAK label matched)")
        leaked = True
        source_url = f"https://github.com/mock-user/mock-leak-repo/blob/main/.env#L12"
    
    # Real GitHub API scan if token is provided and not already simulated
    elif settings.GITHUB_TOKEN and settings.GITHUB_TOKEN != "YOUR_GITHUB_PERSONAL_ACCESS_TOKEN":
        query = f'"{key.key_prefix}"'
        url = "https://api.github.com/search/code"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {settings.GITHUB_TOKEN}"
        }
        params = {
            "q": query,
            "per_page": 1
        }
        
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    total_count = data.get("total_count", 0)
                    
                    if total_count > 0:
                        leaked = True
                        items = data.get("items", [])
                        if items:
                            source_url = items[0].get("html_url")
                        else:
                            source_url = "https://github.com/search"
                else:
                    logger.error(f"GitHub search failed: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Error calling GitHub Search API: {str(e)}")
            # Fail silently to not crash background worker
    else:
        logger.warning(f"GitHub token is missing. Skipping external search for key {key.id}.")

    # Update scan meta
    key.last_scanned_at = datetime.now(timezone.utc).replace(tzinfo=None)
    
    if leaked:
        key.status = "leaked"
        
        # Avoid creating duplicate alert if it was already flagged
        existing_alert = db.query(LeakAlert).filter(
            LeakAlert.api_key_id == key.id,
            LeakAlert.source_url == source_url
        ).first()
        
        if not existing_alert:
            alert = LeakAlert(
                api_key_id=key.id,
                source="github_code_search",
                source_url=source_url,
                resolved=False
            )
            db.add(alert)
            
        logger.warning(f"Key {key.id} marked as LEAKED! Alert generated.")
    
    db.commit()
    
    # Log scan action in audit trails
    log_audit(db, key.user_id, key.id, "scanned")
    
    return leaked

def scan_all_active_keys(db: Session):
    """
    Iterates over all active API keys and runs leak detection.
    """
    logger.info("Starting background scheduled leak scan...")
    active_keys = db.query(APIKey).filter(APIKey.status == "active").all()
    count = 0
    leaked_count = 0
    for key in active_keys:
        try:
            leaked = scan_key_for_leaks(db, key)
            count += 1
            if leaked:
                leaked_count += 1
        except Exception as e:
            logger.error(f"Error scanning key {key.id}: {str(e)}")
            
    logger.info(f"Scheduled scan finished. Processed {count} keys. Detected {leaked_count} leaks.")
