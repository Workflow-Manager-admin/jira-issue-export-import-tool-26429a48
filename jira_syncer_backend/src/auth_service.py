import secrets
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import os
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from .models import UserSession, Project, IssueType
from .jira_service import JiraService
import logging

logger = logging.getLogger(__name__)

class AuthService:
    """Service class for authentication and session management"""
    
    def __init__(self):
        # Generate or load encryption key for sensitive data
        self.encryption_key = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())
        if isinstance(self.encryption_key, str):
            self.encryption_key = self.encryption_key.encode()
        self.cipher = Fernet(self.encryption_key)
        
    # PUBLIC_INTERFACE
    def generate_session_token(self) -> str:
        """Generate a secure session token"""
        return secrets.token_urlsafe(32)
    
    # PUBLIC_INTERFACE
    def encrypt_token(self, token: str) -> str:
        """Encrypt the Jira API token for secure storage"""
        return self.cipher.encrypt(token.encode()).decode()
    
    # PUBLIC_INTERFACE
    def decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt the Jira API token"""
        return self.cipher.decrypt(encrypted_token.encode()).decode()
    
    # PUBLIC_INTERFACE
    def authenticate_user(self, jira_email: str, jira_token: str, jira_domain: str, db: Session) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticate user with Jira and create session
        Returns: (success, session_token, error_message)
        """
        try:
            # Test Jira connection
            jira_service = JiraService(jira_domain, jira_email, jira_token)
            if not jira_service.test_connection():
                return False, None, "Invalid Jira credentials or domain"
            
            # Get user info to validate
            user_info = jira_service.get_user_info()
            if not user_info:
                return False, None, "Failed to retrieve user information from Jira"
            
            # Check if user already has an active session
            existing_session = db.query(UserSession).filter(
                UserSession.jira_email == jira_email,
                UserSession.jira_domain == jira_domain,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).first()
            
            if existing_session:
                # Update existing session
                existing_session.jira_token = self.encrypt_token(jira_token)
                existing_session.expires_at = datetime.utcnow() + timedelta(hours=24)
                db.commit()
                return True, existing_session.session_token, None
            
            # Create new session
            session_token = self.generate_session_token()
            encrypted_token = self.encrypt_token(jira_token)
            
            new_session = UserSession(
                session_token=session_token,
                jira_email=jira_email,
                jira_token=encrypted_token,
                jira_domain=jira_domain,
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_active=True
            )
            
            db.add(new_session)
            db.commit()
            
            return True, session_token, None
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False, None, f"Authentication failed: {str(e)}"
    
    # PUBLIC_INTERFACE
    def get_session(self, session_token: str, db: Session) -> Optional[UserSession]:
        """Get active session by token"""
        return db.query(UserSession).filter(
            UserSession.session_token == session_token,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()
    
    # PUBLIC_INTERFACE
    def refresh_session(self, session_token: str, db: Session) -> bool:
        """Refresh session expiration time"""
        session = self.get_session(session_token, db)
        if session:
            session.expires_at = datetime.utcnow() + timedelta(hours=24)
            db.commit()
            return True
        return False
    
    # PUBLIC_INTERFACE
    def invalidate_session(self, session_token: str, db: Session) -> bool:
        """Invalidate a session"""
        session = self.get_session(session_token, db)
        if session:
            session.is_active = False
            db.commit()
            return True
        return False
    
    # PUBLIC_INTERFACE
    def get_jira_service(self, session: UserSession) -> JiraService:
        """Get Jira service instance for a session"""
        decrypted_token = self.decrypt_token(session.jira_token)
        return JiraService(session.jira_domain, session.jira_email, decrypted_token)
    
    # PUBLIC_INTERFACE
    def cleanup_expired_sessions(self, db: Session) -> int:
        """Clean up expired sessions and return count of cleaned sessions"""
        expired_count = db.query(UserSession).filter(
            UserSession.expires_at < datetime.utcnow()
        ).update({UserSession.is_active: False})
        db.commit()
        return expired_count
