import httpx
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def fetch_openai_admin_completions(api_key: str, date_str: str) -> dict:
    """
    Attempts to query the new OpenAI Admin Usage API for completions.
    Requires an Admin API Key with 'api.usage.read' scope.
    """
    try:
        # Convert date string (YYYY-MM-DD) to start and end UTC timestamps
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        start_time = int(dt.replace(tzinfo=timezone.utc).timestamp())
        end_time = start_time + 86400  # 24 hours duration
        
        url = "https://api.openai.com/v1/organization/usage/completions"
        headers = {
            "Authorization": f"Bearer {api_key}"
        }
        params = {
            "start_time": start_time,
            "end_time": end_time
        }
        
        with httpx.Client(timeout=10.0) as client:
            response = client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                records = data.get("data", [])
                
                total_tokens = 0
                total_requests = 0
                
                for r in records:
                    total_tokens += r.get("input_tokens", 0) + r.get("output_tokens", 0)
                    total_requests += r.get("num_model_requests", 0)
                    
                logger.info(f"Retrieved usage from OpenAI Admin API for {date_str}: {total_tokens} tokens.")
                return {"tokens": total_tokens, "requests": total_requests, "success": True}
            else:
                logger.debug(f"Admin API query returned status {response.status_code}: {response.text}")
    except Exception as e:
        logger.debug(f"Admin API query exception: {str(e)}")
        
    return {"success": False}

def fetch_real_openai_usage(api_key: str, date_str: str) -> dict:
    """
    Dual-mode fetcher. First tries the new Admin usage endpoint.
    If unauthorized or not found, falls back to the legacy usage endpoint.
    """
    # 1. Try modern Admin Usage API
    admin_res = fetch_openai_admin_completions(api_key, date_str)
    if admin_res.get("success"):
        return admin_res

    # 2. Fall back to legacy Usage API
    logger.info(f"Falling back to legacy OpenAI usage endpoint for date {date_str}...")
    url = "https://api.openai.com/v1/usage"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    params = {
        "date": date_str
    }
    
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                records = data.get("data", [])
                
                total_tokens = 0
                total_requests = 0
                
                for record in records:
                    prompt_tokens = record.get("n_context_tokens", 0)
                    completion_tokens = record.get("n_generated_tokens", 0)
                    total_tokens += (prompt_tokens + completion_tokens)
                    total_requests += record.get("n_requests", 0)
                    
                return {"tokens": total_tokens, "requests": total_requests, "success": True}
            else:
                logger.error(f"Legacy usage query failed. Status {response.status_code}: {response.text}")
                return {"error": f"Status {response.status_code}", "tokens": 0, "requests": 0}
    except Exception as e:
        logger.error(f"Legacy usage query failed with exception: {str(e)}")
        return {"error": str(e), "tokens": 0, "requests": 0}
