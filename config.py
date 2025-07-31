"""
Configuration management for GCP Security Audit Tool
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class Config:
    """
    Configuration class to manage environment variables and settings
    """
    
    def __init__(self, project_id: Optional[str] = None):
        # GCP Configuration
        self.project_id = project_id or os.getenv('GCP_PROJECT_ID')
        self.service_account_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        
        # AI Service Configuration
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        
        # Default settings
        self.default_days = 30
        self.max_results = 1000
        
        # Validate required configuration
        self._validate_config()
    
    def _validate_config(self):
        """
        Validate that required configuration is present
        """
        if not self.project_id:
            # Use demo project for testing
            self.project_id = "demo-project-12345"
            logger.info("Using demo project for testing purposes")
        
        if not self.service_account_path:
            logger.warning(
                "GOOGLE_APPLICATION_CREDENTIALS not set. Using default application credentials."
            )
        
        if not self.openai_api_key and not self.gemini_api_key:
            raise ValueError(
                "AI API key is required. Set OPENAI_API_KEY or GEMINI_API_KEY environment variable"
            )
        
        logger.info(f"Configuration loaded for project: {self.project_id}")
    
    @property
    def has_openai_key(self) -> bool:
        """Check if OpenAI API key is available"""
        return bool(self.openai_api_key)
    
    @property
    def has_gemini_key(self) -> bool:
        """Check if Gemini API key is available"""
        return bool(self.gemini_api_key)
