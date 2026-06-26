from sqlalchemy import Column, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class APIKeyUsage(Base):
    __tablename__ = "api_key_usage"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    tokens_used = Column(Integer, nullable=False, default=0)
    request_count = Column(Integer, nullable=False, default=1)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    api_key = relationship("APIKey", back_populates="usages")
