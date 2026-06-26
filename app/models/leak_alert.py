from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class LeakAlert(Base):
    __tablename__ = "leak_alerts"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(50), nullable=False)              # "github_code_search" / "github_secret_scanning"
    source_url = Column(Text, nullable=True)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved = Column(Boolean, default=False)

    api_key = relationship("APIKey", back_populates="leak_alerts")
