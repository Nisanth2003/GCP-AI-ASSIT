"""
Utility functions for the GCP Security Audit Tool
"""

import os
import sys
import json
import logging
from typing import Optional, Dict, Any
from google.auth import default
from google.oauth2 import service_account


def setup_logging(level: int = logging.INFO):
    """
    Set up logging configuration
    
    Args:
        level: Logging level (default: INFO)
    """
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Reduce noise from google cloud libraries
    logging.getLogger('google').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


def validate_gcp_credentials(service_account_path: Optional[str] = None) -> bool:
    """
    Validate GCP credentials
    
    Args:
        service_account_path: Path to service account key file
        
    Returns:
        True if credentials are valid, False otherwise
    """
    try:
        if service_account_path and os.path.exists(service_account_path):
            # Validate service account file
            with open(service_account_path, 'r') as f:
                sa_data = json.load(f)
                required_fields = ['type', 'project_id', 'private_key', 'client_email']
                if not all(field in sa_data for field in required_fields):
                    return False
            
            # Try to create credentials
            credentials = service_account.Credentials.from_service_account_file(
                service_account_path
            )
            return credentials is not None
        else:
            # Try default credentials
            credentials, project = default()
            return credentials is not None
            
    except Exception as e:
        logging.error(f"Credential validation failed: {e}")
        return False


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human readable format
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value = int(bytes_value / 1024.0)
    return f"{bytes_value:.1f} PB"


def safe_get(dictionary: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Safely get a value from a nested dictionary
    
    Args:
        dictionary: Dictionary to search
        key: Key to find (supports dot notation for nested keys)
        default: Default value if key not found
        
    Returns:
        Value from dictionary or default
    """
    try:
        if '.' not in key:
            return dictionary.get(key, default)
        
        keys = key.split('.')
        value = dictionary
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    except Exception:
        return default


def truncate_string(text: str, max_length: int = 100) -> str:
    """
    Truncate string to specified length with ellipsis
    
    Args:
        text: String to truncate
        max_length: Maximum length
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def parse_time_delta(time_str: str) -> int:
    """
    Parse time delta string into days
    
    Args:
        time_str: Time string like "30d", "2w", "6m"
        
    Returns:
        Number of days
    """
    try:
        if time_str.endswith('d'):
            return int(time_str[:-1])
        elif time_str.endswith('w'):
            return int(time_str[:-1]) * 7
        elif time_str.endswith('m'):
            return int(time_str[:-1]) * 30
        elif time_str.endswith('y'):
            return int(time_str[:-1]) * 365
        else:
            return int(time_str)  # Assume days if no unit
    except ValueError:
        return 30  # Default to 30 days


def validate_project_id(project_id: str) -> bool:
    """
    Validate GCP project ID format
    
    Args:
        project_id: Project ID to validate
        
    Returns:
        True if valid format, False otherwise
    """
    import re
    
    # GCP project ID rules:
    # - 6-30 characters
    # - Lowercase letters, digits, hyphens
    # - Must start with lowercase letter
    # - Cannot end with hyphen
    pattern = r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
    return bool(re.match(pattern, project_id))


def get_environment_info() -> Dict[str, Any]:
    """
    Get environment information for debugging
    
    Returns:
        Dictionary with environment details
    """
    return {
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'platform': sys.platform,
        'gcp_project': os.getenv('GCP_PROJECT_ID'),
        'has_service_account': bool(os.getenv('GOOGLE_APPLICATION_CREDENTIALS')),
        'has_openai_key': bool(os.getenv('OPENAI_API_KEY')),
        'has_gemini_key': bool(os.getenv('GEMINI_API_KEY')),
        'working_directory': os.getcwd()
    }
