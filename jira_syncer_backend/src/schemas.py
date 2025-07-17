from pydantic import BaseModel, Field, EmailStr
from datetime import datetime
from typing import List, Optional

# Authentication schemas
class AuthRequest(BaseModel):
    """Schema for authentication request"""
    jira_email: EmailStr = Field(..., description="Jira user email address")
    jira_token: str = Field(..., description="Jira API token")
    jira_domain: str = Field(..., description="Jira domain (e.g., company.atlassian.net)")

class AuthResponse(BaseModel):
    """Schema for authentication response"""
    session_token: str = Field(..., description="Session token for authenticated requests")
    message: str = Field(..., description="Success message")
    expires_at: datetime = Field(..., description="Session expiration time")

# Project schemas
class ProjectResponse(BaseModel):
    """Schema for project information response"""
    id: int = Field(..., description="Internal project ID")
    jira_project_key: str = Field(..., description="Jira project key")
    jira_project_id: str = Field(..., description="Jira project ID")
    name: str = Field(..., description="Project name")
    description: Optional[str] = Field(None, description="Project description")
    project_type: Optional[str] = Field(None, description="Project type")
    lead_name: Optional[str] = Field(None, description="Project lead name")
    url: Optional[str] = Field(None, description="Project URL")
    created_at: datetime = Field(..., description="Created timestamp")

class ProjectListResponse(BaseModel):
    """Schema for project list response"""
    projects: List[ProjectResponse] = Field(..., description="List of projects")
    total: int = Field(..., description="Total number of projects")

# Issue type schemas
class IssueTypeResponse(BaseModel):
    """Schema for issue type response"""
    id: int = Field(..., description="Internal issue type ID")
    jira_issue_type_id: str = Field(..., description="Jira issue type ID")
    name: str = Field(..., description="Issue type name")
    description: Optional[str] = Field(None, description="Issue type description")
    icon_url: Optional[str] = Field(None, description="Issue type icon URL")
    subtask: bool = Field(..., description="Whether this is a subtask type")

class IssueTypeListResponse(BaseModel):
    """Schema for issue type list response"""
    issue_types: List[IssueTypeResponse] = Field(..., description="List of issue types")
    total: int = Field(..., description="Total number of issue types")

# Session schemas
class SessionInfo(BaseModel):
    """Schema for session information"""
    session_token: str = Field(..., description="Session token")
    jira_email: str = Field(..., description="Jira user email")
    jira_domain: str = Field(..., description="Jira domain")
    created_at: datetime = Field(..., description="Session creation time")
    expires_at: datetime = Field(..., description="Session expiration time")
    is_active: bool = Field(..., description="Session active status")

# Error schemas
class ErrorResponse(BaseModel):
    """Schema for error responses"""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    code: Optional[str] = Field(None, description="Error code")
