import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timezone

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scans.db")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    failed_login_attempts = Column(Integer, default=0)
    lockout_until = Column(DateTime, nullable=True)     
    email = Column(String, unique=True, index=True)       
    scans = relationship("ScanRecord", back_populates="owner")

class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_type = Column(String)
    risk_status = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
     
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="scans")

Base.metadata.create_all(bind=engine)