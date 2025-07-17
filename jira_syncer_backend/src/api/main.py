from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
import logging
import os

from ..database import get_db, create_tables
from ..schemas import (
    AuthRequest, AuthResponse, ProjectListResponse, ProjectResponse,
    IssueTypeListResponse, IssueTypeResponse, SessionInfo, ErrorResponse
)
from ..auth_service import AuthService
from ..models import UserSession, Project, IssueType
from ..jira_service import JiraService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Jira Issue Export/Import Tool API",
    description="A REST API for exporting and importing Jira issues with authentication and project management",
    version="1.0.0",
    openapi_tags=[
        {
            "name": "authentication",
            "description": "User authentication and session management endpoints"
        },
        {
            "name": "projects",
            "description": "Project listing and management endpoints"
        },
        {
            "name": "issue-types",
            "description": "Issue type discovery and management endpoints"
        }
    ]
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
auth_service = AuthService()
security = HTTPBearer()

# Create tables on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database tables on startup"""
    try:
        create_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {str(e)}")

# PUBLIC_INTERFACE
def get_current_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> UserSession:
    """
    Dependency to get current user session from Authorization header
    """
    session_token = credentials.credentials
    session = auth_service.get_session(session_token, db)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session

@app.get("/", tags=["health"])
async def health_check():
    """Health check endpoint"""
    return {"message": "Jira Issue Export/Import Tool API is running", "timestamp": datetime.utcnow()}

# Authentication endpoints
@app.post("/api/auth/login", 
         response_model=AuthResponse, 
         tags=["authentication"],
         summary="Authenticate user with Jira credentials",
         description="Authenticate user using Jira email, API token, and domain. Returns session token for subsequent requests.")
async def login(auth_request: AuthRequest, db: Session = Depends(get_db)):
    """
    Authenticate user with Jira credentials and create session
    
    - **jira_email**: User's Jira email address
    - **jira_token**: User's Jira API token
    - **jira_domain**: Jira domain (e.g., company.atlassian.net)
    """
    try:
        success, session_token, error = auth_service.authenticate_user(
            auth_request.jira_email,
            auth_request.jira_token,
            auth_request.jira_domain,
            db
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error or "Authentication failed"
            )
        
        # Get session for expiration time
        session = auth_service.get_session(session_token, db)
        
        return AuthResponse(
            session_token=session_token,
            message="Authentication successful",
            expires_at=session.expires_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )

@app.post("/api/auth/refresh", 
         response_model=dict, 
         tags=["authentication"],
         summary="Refresh session token",
         description="Refresh the expiration time of the current session")
async def refresh_session(
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Refresh current session expiration time
    """
    try:
        success = auth_service.refresh_session(current_session.session_token, db)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to refresh session"
            )
        
        return {"message": "Session refreshed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during session refresh"
        )

@app.post("/api/auth/logout", 
         response_model=dict, 
         tags=["authentication"],
         summary="Logout user",
         description="Invalidate current session and logout user")
async def logout(
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Logout user and invalidate session
    """
    try:
        success = auth_service.invalidate_session(current_session.session_token, db)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to logout"
            )
        
        return {"message": "Logged out successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during logout"
        )

@app.get("/api/auth/session", 
        response_model=SessionInfo, 
        tags=["authentication"],
        summary="Get current session info",
        description="Get information about the current user session")
async def get_session_info(current_session: UserSession = Depends(get_current_session)):
    """
    Get current session information
    """
    return SessionInfo(
        session_token=current_session.session_token,
        jira_email=current_session.jira_email,
        jira_domain=current_session.jira_domain,
        created_at=current_session.created_at,
        expires_at=current_session.expires_at,
        is_active=current_session.is_active
    )

# Project endpoints
@app.get("/api/projects", 
        response_model=ProjectListResponse, 
        tags=["projects"],
        summary="Get all projects",
        description="Retrieve all Jira projects accessible to the authenticated user")
async def get_projects(
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Get all projects accessible to the authenticated user
    """
    try:
        # Get Jira service for current session
        jira_service = auth_service.get_jira_service(current_session)
        
        # Fetch projects from Jira
        jira_projects = jira_service.get_projects()
        
        # Store/update projects in database
        projects_list = []
        for jira_project in jira_projects:
            # Check if project already exists
            existing_project = db.query(Project).filter(
                Project.session_id == current_session.id,
                Project.jira_project_key == jira_project.get('key')
            ).first()
            
            if existing_project:
                # Update existing project
                existing_project.name = jira_project.get('name', '')
                existing_project.description = jira_project.get('description', '')
                existing_project.project_type = jira_project.get('projectTypeKey', '')
                existing_project.lead_name = jira_project.get('lead', {}).get('displayName', '')
                existing_project.url = jira_project.get('self', '')
                project = existing_project
            else:
                # Create new project
                project = Project(
                    session_id=current_session.id,
                    jira_project_key=jira_project.get('key'),
                    jira_project_id=jira_project.get('id'),
                    name=jira_project.get('name', ''),
                    description=jira_project.get('description', ''),
                    project_type=jira_project.get('projectTypeKey', ''),
                    lead_name=jira_project.get('lead', {}).get('displayName', ''),
                    url=jira_project.get('self', '')
                )
                db.add(project)
            
            projects_list.append(project)
        
        db.commit()
        
        # Convert to response format
        project_responses = [
            ProjectResponse(
                id=project.id,
                jira_project_key=project.jira_project_key,
                jira_project_id=project.jira_project_id,
                name=project.name,
                description=project.description,
                project_type=project.project_type,
                lead_name=project.lead_name,
                url=project.url,
                created_at=project.created_at
            ) for project in projects_list
        ]
        
        return ProjectListResponse(
            projects=project_responses,
            total=len(project_responses)
        )
        
    except Exception as e:
        logger.error(f"Error fetching projects: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch projects"
        )

@app.get("/api/projects/{project_key}", 
        response_model=ProjectResponse, 
        tags=["projects"],
        summary="Get project details",
        description="Get detailed information about a specific project")
async def get_project_details(
    project_key: str,
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific project
    """
    try:
        # Get project from database
        project = db.query(Project).filter(
            Project.session_id == current_session.id,
            Project.jira_project_key == project_key
        ).first()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        return ProjectResponse(
            id=project.id,
            jira_project_key=project.jira_project_key,
            jira_project_id=project.jira_project_id,
            name=project.name,
            description=project.description,
            project_type=project.project_type,
            lead_name=project.lead_name,
            url=project.url,
            created_at=project.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching project details: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch project details"
        )

# Issue type endpoints
@app.get("/api/projects/{project_key}/issue-types", 
        response_model=IssueTypeListResponse, 
        tags=["issue-types"],
        summary="Get issue types for project",
        description="Get all issue types available for a specific project")
async def get_project_issue_types(
    project_key: str,
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Get all issue types for a specific project
    """
    try:
        # Get project from database
        project = db.query(Project).filter(
            Project.session_id == current_session.id,
            Project.jira_project_key == project_key
        ).first()
        
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Get Jira service for current session
        jira_service = auth_service.get_jira_service(current_session)
        
        # Fetch issue types from Jira
        jira_issue_types = jira_service.get_issue_types_for_project(project_key)
        
        # Store/update issue types in database
        issue_types_list = []
        for jira_issue_type in jira_issue_types:
            # Check if issue type already exists
            existing_issue_type = db.query(IssueType).filter(
                IssueType.project_id == project.id,
                IssueType.jira_issue_type_id == jira_issue_type.get('id')
            ).first()
            
            if existing_issue_type:
                # Update existing issue type
                existing_issue_type.name = jira_issue_type.get('name', '')
                existing_issue_type.description = jira_issue_type.get('description', '')
                existing_issue_type.icon_url = jira_issue_type.get('iconUrl', '')
                existing_issue_type.subtask = jira_issue_type.get('subtask', False)
                issue_type = existing_issue_type
            else:
                # Create new issue type
                issue_type = IssueType(
                    project_id=project.id,
                    jira_issue_type_id=jira_issue_type.get('id'),
                    name=jira_issue_type.get('name', ''),
                    description=jira_issue_type.get('description', ''),
                    icon_url=jira_issue_type.get('iconUrl', ''),
                    subtask=jira_issue_type.get('subtask', False)
                )
                db.add(issue_type)
            
            issue_types_list.append(issue_type)
        
        db.commit()
        
        # Convert to response format
        issue_type_responses = [
            IssueTypeResponse(
                id=issue_type.id,
                jira_issue_type_id=issue_type.jira_issue_type_id,
                name=issue_type.name,
                description=issue_type.description,
                icon_url=issue_type.icon_url,
                subtask=issue_type.subtask
            ) for issue_type in issue_types_list
        ]
        
        return IssueTypeListResponse(
            issue_types=issue_type_responses,
            total=len(issue_type_responses)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching issue types: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch issue types"
        )

# Cleanup endpoint for maintenance
@app.post("/api/admin/cleanup-sessions", 
         response_model=dict, 
         tags=["admin"],
         summary="Cleanup expired sessions",
         description="Clean up expired user sessions (admin endpoint)")
async def cleanup_expired_sessions(db: Session = Depends(get_db)):
    """
    Clean up expired sessions (maintenance endpoint)
    """
    try:
        cleaned_count = auth_service.cleanup_expired_sessions(db)
        return {"message": f"Cleaned up {cleaned_count} expired sessions"}
        
    except Exception as e:
        logger.error(f"Error cleaning up sessions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clean up sessions"
        )
