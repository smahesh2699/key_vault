import httpx
import logging

logger = logging.getLogger(__name__)

def detect_billing_plan(service: str, api_key: str) -> str:
    """
    Attempts to auto-detect the billing plan of an API key by making a lightweight API call.
    Returns "free" or "paid". Defaults to "free" on failure or unrecognized service.
    """
    service_lower = service.lower()
    
    # 1. AWS and Stripe are always paid (pay-as-you-go, no free tier limits)
    if "aws" in service_lower or "stripe" in service_lower:
        return "paid"
        
    # 2. GitHub is free of charge
    if "github" in service_lower:
        return "free"

    # 3. OpenAI key detection via rate-limit headers probe
    if "openai" in service_lower:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}"}
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1
            }
            with httpx.Client(timeout=5.0) as client:
                response = client.post(url, json=payload, headers=headers)
                
            if response.status_code == 200:
                # Check x-ratelimit-limit-requests header
                limit_requests = response.headers.get("x-ratelimit-limit-requests")
                if limit_requests:
                    try:
                        limit_val = int(limit_requests)
                        # OpenAI Free Tier is 3 RPM. Paid Tier 1 is at least 500 RPM (up to 10000 RPM).
                        if limit_val > 10:
                            return "paid"
                    except ValueError:
                        pass
                        
                # Check x-ratelimit-limit-tokens header
                limit_tokens = response.headers.get("x-ratelimit-limit-tokens")
                if limit_tokens:
                    try:
                        limit_val = int(limit_tokens)
                        # OpenAI Free Tier is 40,000 TPM. Paid Tier is higher.
                        if limit_val > 50000:
                            return "paid"
                    except ValueError:
                        pass
                
                return "free"
            elif response.status_code == 429:
                # 429 Insufficient Quota: key works but account has no credits/billing.
                # This is standard for expired free trials or unconfigured accounts.
                return "free"
        except Exception as e:
            logger.error(f"Error auto-detecting OpenAI plan: {str(e)}")
            return "free"

    # 4. Google Cloud / Gemini plan detection
    if "google" in service_lower or "gemini" in service_lower:
        try:
            # We probe the Gemini API to check if it's functional or returns quota errors.
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": "ping"}]}]
            }
            with httpx.Client(timeout=5.0) as client:
                response = client.post(url, json=payload)
                
            if response.status_code == 429:
                # Check if error message explicitly points to free tier requests quota
                err_text = response.text.lower()
                if "free_tier" in err_text:
                    return "free"
                elif "pay_as_you_go" in err_text:
                    return "paid"
                    
            # Default fallback for Gemini is "free" (AI Studio default).
            # Users can manually toggle to paid if they have upgraded.
            return "free"
        except Exception as e:
            logger.error(f"Error probing Google Gemini plan: {str(e)}")
            return "free"

    # Default fallback
    return "free"
