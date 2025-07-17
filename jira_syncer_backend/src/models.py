from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class UserSession(Base):
    """Model for storing user session information"""
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String(255), unique=True, index=True)
    jira_email = Column(String(255), nullable=False)
    jira_token = Column(Text, nullable=False)  # Encrypted API token
    jira_domain = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    projects = relationship("Project", back_populates="session")

class Project(Base):
    """Model for storing Jira project information"""
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("user_sessions.id"))
    jira_project_key = Column(String(50), nullable=False)
    jira_project_id = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    project_type = Column(String(100))
    lead_name = Column(String(255))
    url = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    session = relationship("UserSession", back_populates="projects")
    issue_types = relationship("IssueType", back_populates="project")

class IssueType(Base):
    """Model for storing issue type information for projects"""
    __tablename__ = "issue_types"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    jira_issue_type_id = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    icon_url = Column(String(500))
    subtask = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="issue_types")
