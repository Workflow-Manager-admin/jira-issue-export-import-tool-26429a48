import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import os
from typing import Optional, Tuple, Dict
from .jira_service import JiraService
import logging

logger = logging.getLogger(__name__)

class AuthService:
    """Service class for authentication and session management using in-memory storage"""
    
    def __init__(self):
        # Generate or load encryption key for sensitive data
        self.encryption_key = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())
        if isinstance(self.encryption_key, str):
            self.encryption_key = self.encryption_key.encode()
        self.cipher = Fernet(self.encryption_key)
        
        # In-memory session storage
        self.sessions: Dict[str, dict] = {}
        
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
    def authenticate_user(self, jira_email: str, jira_token: str, jira_domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
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
            existing_session_token = None
            current_time = datetime.utcnow()
            
            for token, session_data in self.sessions.items():
                if (session_data['jira_email'] == jira_email and 
                    session_data['jira_domain'] == jira_domain and 
                    session_data['is_active'] and 
                    session_data['expires_at'] > current_time):
                    existing_session_token = token
                    break
            
            if existing_session_token:
                # Update existing session
                self.sessions[existing_session_token]['jira_token'] = self.encrypt_token(jira_token)
                self.sessions[existing_session_token]['expires_at'] = current_time + timedelta(hours=24)
                return True, existing_session_token, None
            
            # Create new session
            session_token = self.generate_session_token()
            encrypted_token = self.encrypt_token(jira_token)
            
            session_data = {
                'session_token': session_token,
                'jira_email': jira_email,
                'jira_token': encrypted_token,
                'jira_domain': jira_domain,
                'created_at': current_time,
                'expires_at': current_time + timedelta(hours=24),
                'is_active': True
            }
            
            self.sessions[session_token] = session_data
            
            return True, session_token, None
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False, None, f"Authentication failed: {str(e)}"
    
    # PUBLIC_INTERFACE
    def get_session(self, session_token: str) -> Optional[dict]:
        """Get active session by token"""
        session_data = self.sessions.get(session_token)
        if session_data and session_data['is_active'] and session_data['expires_at'] > datetime.utcnow():
            return session_data
        return None
    
    # PUBLIC_INTERFACE
    def refresh_session(self, session_token: str) -> bool:
        """Refresh session expiration time"""
        session = self.get_session(session_token)
        if session:
            session['expires_at'] = datetime.utcnow() + timedelta(hours=24)
            return True
        return False
    
    # PUBLIC_INTERFACE
    def invalidate_session(self, session_token: str) -> bool:
        """Invalidate a session"""
        session = self.get_session(session_token)
        if session:
            session['is_active'] = False
            return True
        return False
    
    # PUBLIC_INTERFACE
    def get_jira_service(self, session: dict) -> JiraService:
        """Get Jira service instance for a session"""
        decrypted_token = self.decrypt_token(session['jira_token'])
        return JiraService(session['jira_domain'], session['jira_email'], decrypted_token)
    
    # PUBLIC_INTERFACE
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count of cleaned sessions"""
        current_time = datetime.utcnow()
        expired_count = 0
        
        for session_data in self.sessions.values():
            if session_data['expires_at'] < current_time:
                session_data['is_active'] = False
                expired_count += 1
        
        return expired_count
