from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    label = Column(String(100), nullable=False)
    service = Column(String(50), nullable=False)
    key_fingerprint = Column(String(64), nullable=False, index=True)   # SHA-256 hash
    key_prefix = Column(String(20), nullable=True)                      # e.g., sk-proj-
    encrypted_value = Column(Text, nullable=False)                      # Fernet-encrypted raw key
    status = Column(String(20), default="active")                       # active, revoked, leaked, expired
    billing_plan = Column(String(20), default="free")                   # free, paid
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_rotated_at = Column(DateTime(timezone=True), nullable=True)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="api_keys")
    leak_alerts = relationship("LeakAlert", back_populates="api_key", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="api_key", cascade="all, delete-orphan")
    usages = relationship("APIKeyUsage", back_populates="api_key", cascade="all, delete-orphan")
