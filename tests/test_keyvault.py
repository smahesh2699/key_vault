import pytest
import os
import sys
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add project root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.core.database import Base, get_db
from app.core.security import hash_password, verify_password, encrypt_key_value, decrypt_key_value
from app.models.user import User
from app.models.api_key import APIKey
from app.models.leak_alert import LeakAlert
from app.models.audit_log import AuditLog

# Setup test database file
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_keyvault.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    # Create tables
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Drop tables
        Base.metadata.drop_all(bind=engine)
        # Clean up database file
        if os.path.exists("test_keyvault.db"):
            try:
                os.remove("test_keyvault.db")
            except OSError:
                pass

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture(autouse=True)
def mock_detect_billing_plan():
    from unittest.mock import patch
    with patch("app.routers.keys.detect_billing_plan", return_value="free") as mock:
        yield mock

# --- Unit Tests: Security ---

def test_password_hashing():
    password = "SuperSafePassword123"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

def test_fernet_encryption():
    secret = "sk-proj-xyz123456789abc"
    encrypted = encrypt_key_value(secret)
    assert encrypted != secret
    decrypted = decrypt_key_value(encrypted)
    assert decrypted == secret

# --- Integration Tests: Auth Flow ---

def test_user_registration_and_login(client):
    # Register new user
    response = client.post("/auth/register", data={
        "name": "Alice Developer",
        "email": "alice@example.com",
        "password": "alicepassword123",
        "confirm_password": "alicepassword123"
    }, follow_redirects=False)
    
    assert response.status_code == 303
    assert response.headers["Location"].startswith("/login")

    # Verify duplicate email is blocked
    response_dup = client.post("/auth/register", data={
        "name": "Alice Duplicate",
        "email": "alice@example.com",
        "password": "alicepassword123",
        "confirm_password": "alicepassword123"
    })
    assert response_dup.status_code == 200
    assert b"Email is already registered" in response_dup.content

    # Log in
    response_login = client.post("/auth/login", data={
        "email": "alice@example.com",
        "password": "alicepassword123"
    }, follow_redirects=False)
    
    assert response_login.status_code == 303
    assert response_login.headers["Location"] == "/dashboard"
    
    # Assert auth cookies are set
    cookies = response_login.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies

# --- Integration Tests: Key Management Vault ---

def test_key_crud_vault(client, db_session):
    # Create user
    hashed_pwd = hash_password("alicepassword123")
    user = User(name="Alice", email="alice@example.com", password_hash=hashed_pwd)
    db_session.add(user)
    db_session.commit()

    # Authenticate client
    client.post("/auth/login", data={"email": "alice@example.com", "password": "alicepassword123"})

    # Store API key
    response = client.post("/keys", data={
        "label": "OpenAI Production",
        "service": "OpenAI",
        "value": "sk-proj-openai-production-secret-key-12345"
    })
    
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "success"
    key_id = res_data["key"]["id"]

    # Verify key was written securely to DB
    db_key = db_session.query(APIKey).filter(APIKey.id == key_id).first()
    assert db_key is not None
    assert db_key.label == "OpenAI Production"
    assert db_key.key_prefix == "sk-proj-openai-p"
    # Plaintext key should not be in the database
    assert db_key.encrypted_value != "sk-proj-openai-production-secret-key-12345"
    assert decrypt_key_value(db_key.encrypted_value) == "sk-proj-openai-production-secret-key-12345"
    assert db_key.billing_plan == "free"

    # Verify duplicate fingerprint is blocked
    response_dup = client.post("/keys", data={
        "label": "OpenAI Duplicate",
        "service": "OpenAI",
        "value": "sk-proj-openai-production-secret-key-12345"
    })
    assert response_dup.status_code == 400
    assert "already been stored" in response_dup.json()["error"]

    # Verify Audit log registers creation
    db_log = db_session.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.api_key_id == key_id,
        AuditLog.action == "created"
    ).first()
    assert db_log is not None

    # Reveal API key with valid password recheck
    response_reveal = client.post(f"/keys/{key_id}/reveal", data={"password": "alicepassword123"})
    assert response_reveal.status_code == 200
    assert response_reveal.json()["value"] == "sk-proj-openai-production-secret-key-12345"

    # Reveal key with invalid password
    response_reveal_fail = client.post(f"/keys/{key_id}/reveal", data={"password": "wrongpassword"})
    assert response_reveal_fail.status_code == 400
    assert "Incorrect password" in response_reveal_fail.json()["error"]

    # Update metadata
    response_update = client.post(f"/keys/{key_id}/update", data={
        "label": "OpenAI Production (Rotated)",
        "service": "OpenAI",
        "billing_plan": "paid"
    })
    assert response_update.status_code == 200
    db_session.refresh(db_key)
    assert db_key.label == "OpenAI Production (Rotated)"
    assert db_key.billing_plan == "paid"

    # Revoke key
    response_revoke = client.post(f"/keys/{key_id}/revoke")
    assert response_revoke.status_code == 200
    db_session.refresh(db_key)
    assert db_key.status == "revoked"

    # Delete key
    response_delete = client.delete(f"/keys/{key_id}")
    assert response_delete.status_code == 200
    db_deleted_key = db_session.query(APIKey).filter(APIKey.id == key_id).first()
    assert db_deleted_key is None

# --- Integration Tests: Leak Detection Simulator ---

def test_leak_detection_simulation(client, db_session):
    # Create user
    hashed_pwd = hash_password("alicepassword123")
    user = User(name="Alice", email="alice@example.com", password_hash=hashed_pwd)
    db_session.add(user)
    db_session.commit()

    # Authenticate client
    client.post("/auth/login", data={"email": "alice@example.com", "password": "alicepassword123"})

    # Store API key that triggers simulation (label contains TEST_LEAK)
    response = client.post("/keys", data={
        "label": "My TEST_LEAK Secret Key",
        "service": "Stripe",
        "value": "sk_test_51Nx123456789abcdefghijklmnopqrstuvwxyz"
    })
    assert response.status_code == 200
    key_id = response.json()["key"]["id"]

    # Trigger manual scan
    response_scan = client.post(f"/keys/{key_id}/scan-now")
    assert response_scan.status_code == 200
    assert response_scan.json()["leaked"] is True
    assert "flagged as leaked" in response_scan.json()["message"]

    # Verify key status is shifted to leaked
    db_key = db_session.query(APIKey).filter(APIKey.id == key_id).first()
    assert db_key.status == "leaked"

    # Verify LeakAlert record is generated
    alert = db_session.query(LeakAlert).filter(LeakAlert.api_key_id == key_id).first()
    assert alert is not None
    assert alert.source == "github_code_search"
    assert "mock-leak-repo" in alert.source_url
    assert alert.resolved is False

    # Resolve Alert
    response_resolve = client.post(f"/alerts/{alert.id}/resolve")
    assert response_resolve.status_code == 200
    
    # Verify alert is resolved and key status returned to active
    db_session.refresh(alert)
    db_session.refresh(db_key)
    assert alert.resolved is True
    assert db_key.status == "active"

def test_detect_billing_plan():
    from app.services.plan_detector import detect_billing_plan
    from unittest.mock import patch, MagicMock

    # 1. AWS & Stripe should return 'paid' immediately
    assert detect_billing_plan("AWS", "any-key") == "paid"
    assert detect_billing_plan("Stripe", "any-key") == "paid"
    
    # 2. GitHub should return 'free'
    assert detect_billing_plan("GitHub", "any-key") == "free"

    # 3. Test OpenAI detect_billing_plan with mocked responses
    with patch("httpx.Client.post") as mock_post:
        # Mock free tier (low rate limit)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"x-ratelimit-limit-requests": "3", "x-ratelimit-limit-tokens": "40000"}
        mock_post.return_value = mock_resp
        
        assert detect_billing_plan("OpenAI", "mock-key") == "free"
        
        # Mock paid tier (high rate limit)
        mock_resp.headers = {"x-ratelimit-limit-requests": "500", "x-ratelimit-limit-tokens": "200000"}
        assert detect_billing_plan("OpenAI", "mock-key") == "paid"

        # Mock insufficient quota (429)
        mock_resp_429 = MagicMock()
        mock_resp_429.status_code = 429
        mock_post.return_value = mock_resp_429
        assert detect_billing_plan("OpenAI", "mock-key") == "free"

    # 4. Test Gemini detect_billing_plan with mocked responses
    with patch("httpx.Client.post") as mock_post:
        # Mock free tier quota exceeded response (429 containing "free_tier")
        mock_resp_429 = MagicMock()
        mock_resp_429.status_code = 429
        mock_resp_429.text = "Quota exceeded for generativelanguage.googleapis.com/generate_content_free_tier_requests"
        mock_post.return_value = mock_resp_429
        
        assert detect_billing_plan("GoogleCloud", "mock-key") == "free"

