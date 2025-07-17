import requests
import base64
from typing import List, Dict, Optional
from requests.auth import HTTPBasicAuth
import logging

logger = logging.getLogger(__name__)

class JiraService:
    """Service class for interacting with Jira API"""
    
    def __init__(self, jira_domain: str, email: str, api_token: str):
        self.jira_domain = jira_domain.rstrip('/')
        self.email = email
        self.api_token = api_token
        self.base_url = f"https://{self.jira_domain}"
        self.auth = HTTPBasicAuth(email, api_token)
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    # PUBLIC_INTERFACE
    def test_connection(self) -> bool:
        """Test if the Jira connection is valid"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/myself",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Connection test failed: {str(e)}")
            return False

    # PUBLIC_INTERFACE
    def get_user_info(self) -> Optional[Dict]:
        """Get current user information"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/myself",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Failed to get user info: {str(e)}")
            return None

    # PUBLIC_INTERFACE
    def get_projects(self) -> List[Dict]:
        """Get all projects accessible to the user"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/project",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Failed to get projects: {str(e)}")
            return []

    # PUBLIC_INTERFACE
    def get_project_details(self, project_key: str) -> Optional[Dict]:
        """Get detailed information about a specific project"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/project/{project_key}",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Failed to get project details for {project_key}: {str(e)}")
            return None

    # PUBLIC_INTERFACE
    def get_issue_types_for_project(self, project_key: str) -> List[Dict]:
        """Get all issue types for a specific project"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/project/{project_key}/issuetypes",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Failed to get issue types for {project_key}: {str(e)}")
            return []

    # PUBLIC_INTERFACE
    def get_all_issue_types(self) -> List[Dict]:
        """Get all issue types available in the Jira instance"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/issuetype",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            logger.error(f"Failed to get all issue types: {str(e)}")
            return []

    # PUBLIC_INTERFACE
    def validate_project_access(self, project_key: str) -> bool:
        """Validate if the user has access to the specified project"""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/project/{project_key}",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to validate project access for {project_key}: {str(e)}")
            return False
