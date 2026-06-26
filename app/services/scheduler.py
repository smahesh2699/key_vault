import logging
from apscheduler.schedulers.background import BackgroundScheduler
from app.core.database import SessionLocal
from app.services.leak_scanner import scan_all_active_keys

logger = logging.getLogger(__name__)

# Initialize background scheduler
scheduler = BackgroundScheduler()

def run_scheduled_scan():
    """Wrapper to instantiate a DB session and run the scan job."""
    db = SessionLocal()
    try:
        scan_all_active_keys(db)
    except Exception as e:
        logger.error(f"Failed to execute background scanner: {str(e)}")
    finally:
        db.close()

def start_scheduler():
    """Start the periodic background scanning job."""
    if not scheduler.running:
        # Check every 6 hours by default.
        # Can be set to a shorter interval for testing/demo if desired, e.g. minutes=10.
        scheduler.add_job(
            run_scheduled_scan, 
            "interval", 
            hours=6, 
            id="leak_scan_job", 
            replace_existing=True
        )
        scheduler.start()
        logger.info("APScheduler background worker initialized and running.")

def stop_scheduler():
    """Shut down the background scheduler."""
    if scheduler.running:
        scheduler.shutdown()
        logger.info("APScheduler background worker stopped.")
