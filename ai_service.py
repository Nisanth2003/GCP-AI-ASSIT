"""
AI Service for converting natural language queries to GCP audit commands
"""

import json
import logging
import os
from typing import Dict, List, Any
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseAIProvider(ABC):
    """Base class for AI providers"""
    
    @abstractmethod
    def generate_commands(self, user_query: str) -> Dict[str, Any]:
        """Generate audit commands from user query"""
        pass
    
    def _is_valid_security_query(self, query: str) -> bool:
        """
        Validate that the query is related to security auditing and safe
        """
        if not query or len(query.strip()) == 0:
            return False
        
        query_lower = query.lower().strip()
        
        # Check for minimum length
        if len(query_lower) < 3:
            return False
        
        # Block obviously malicious or irrelevant queries
        blocked_patterns = [
            'delete', 'remove', 'destroy', 'hack', 'exploit', 'attack',
            'create user', 'add user', 'modify', 'update', 'set password',
            'drop table', 'truncate', 'alter table', 'grant permission',
            'weather', 'recipe', 'joke', 'story', 'poem', 'song',
            'what is', 'how to', 'explain', 'define', 'tutorial'
        ]
        
        for pattern in blocked_patterns:
            if pattern in query_lower:
                return False
        
        # Look for security/audit related keywords
        security_keywords = [
            'user', 'users', 'account', 'accounts', 'permission', 'permissions',
            'role', 'roles', 'policy', 'policies', 'access', 'login', 'inactive',
            'mfa', 'multi-factor', '2fa', 'two-factor', 'authentication',
            'key', 'keys', 'rotate', 'rotation', 'old', 'expired',
            'service', 'quota', 'quotas', 'limit', 'limits', 'usage',
            'support', 'plan', 'billing', 'admin', 'administrator',
            'security', 'audit', 'check', 'list', 'show', 'view', 'get'
        ]
        
        # Query must contain at least one security keyword
        has_security_keyword = any(keyword in query_lower for keyword in security_keywords)
        
        return has_security_keyword


class OpenAIProvider(BaseAIProvider):
    """OpenAI-based AI provider"""
    
    def __init__(self):
        from openai import OpenAI
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    
    def generate_commands(self, user_query: str) -> Dict[str, Any]:
        """
        Generate GCP audit commands using OpenAI
        """
        # First validate the query
        if not self._is_valid_security_query(user_query):
            return {
                "audit_type": "invalid_query",
                "commands": [],
                "parameters": {},
                "description": "Query is not related to GCP security auditing or contains invalid content",
                "error": "Invalid or unsupported query"
            }

        system_prompt = """You are a senior DevOps engineer and GCP security expert. 
        Convert user requests into structured audit commands for Google Cloud Platform.

        Available audit types and their purposes:
        - inactive_users: Find users who haven't logged in for X days
        - mfa_status: Check users without MFA enabled
        - key_rotation: Check service account keys not rotated in X days
        - service_quotas: View current service limits and quotas
        - support_plan: View GCP support plan details
        - admin_policies: List policies and roles with admin access

        IMPORTANT RULES:
        1. Only respond with one of the exact audit types listed above
        2. If the query doesn't match any audit type, use "unsupported_query"
        3. Extract time periods (days) from queries when mentioned
        4. Always provide safe, read-only operations only

        Respond with JSON in this exact format:
        {
            "audit_type": "one of the types above or unsupported_query",
            "commands": ["list of safe gcloud commands or API calls"],
            "parameters": {"key": "value pairs for the audit function"},
            "description": "human readable description of what will be audited"
        }

        Examples:
        - "show inactive users for 90 days" → audit_type: "inactive_users", parameters: {"days": 90}
        - "list users without MFA" → audit_type: "mfa_status"
        - "check old service account keys" → audit_type: "key_rotation"
        - "what's my support plan" → audit_type: "support_plan"
        """
        
        try:
            # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            # do not change this unless explicitly requested by the user
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_query}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            
            content = response.choices[0].message.content
            if not content:
                raise ValueError("Empty response from OpenAI")
            
            result = json.loads(content)
            logger.debug(f"OpenAI response: {result}")
            return result
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            # Return a fallback response instead of raising
            return {
                "audit_type": "api_error",
                "commands": [],
                "parameters": {},
                "description": f"AI service error: {str(e)}",
                "error": f"OpenAI API error: {e}"
            }


class GeminiProvider(BaseAIProvider):
    """Gemini-based AI provider"""
    
    def __init__(self):
        import google.genai as genai
        from google.genai import types
        self.client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))
        self.types = types
    
    def generate_commands(self, user_query: str) -> Dict[str, Any]:
        """
        Generate GCP audit commands using Gemini
        """
        # First validate the query
        if not self._is_valid_security_query(user_query):
            return {
                "audit_type": "invalid_query",
                "commands": [],
                "parameters": {},
                "description": "Query is not related to GCP security auditing or contains invalid content",
                "error": "Invalid or unsupported query"
            }

        system_prompt = """You are a senior DevOps engineer and GCP security expert. 
        Convert user requests into structured audit commands for Google Cloud Platform.

        Available audit types and their purposes:
        - inactive_users: Find users who haven't logged in for X days
        - mfa_status: Check users without MFA enabled
        - key_rotation: Check service account keys not rotated in X days
        - service_quotas: View current service limits and quotas
        - support_plan: View GCP support plan details
        - admin_policies: List policies and roles with admin access

        IMPORTANT RULES:
        1. Only respond with one of the exact audit types listed above
        2. If the query doesn't match any audit type, use "unsupported_query"
        3. Extract time periods (days) from queries when mentioned
        4. Always provide safe, read-only operations only
        5. NEVER use placeholder values like ORGANIZATION_ID, YOUR_PROJECT_ID, etc.
        6. Use actual function calls instead of gcloud commands when possible

        For each audit type, use these EXACT patterns:
        - inactive_users: ["check_inactive_users"]
        - mfa_status: ["check_mfa_status"]  
        - key_rotation: ["check_key_rotation"]
        - service_quotas: ["get_service_quotas"]
        - support_plan: ["get_support_plan"]
        - admin_policies: ["list_admin_policies"]

        Respond with JSON in this exact format:
        {
            "audit_type": "one of the types above or unsupported_query",
            "commands": ["use function names from patterns above"],
            "parameters": {"key": "value pairs for the audit function"},
            "description": "human readable description of what will be audited"
        }

        Examples:
        - "show inactive users for 90 days" → audit_type: "inactive_users", commands: ["check_inactive_users"], parameters: {"days": 90}
        - "list users without MFA" → audit_type: "mfa_status", commands: ["check_mfa_status"]
        - "check old service account keys" → audit_type: "key_rotation", commands: ["check_key_rotation"]
        - "what's my support plan" → audit_type: "support_plan", commands: ["get_support_plan"]
        """
        
        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=[
                    self.types.Content(role="user", parts=[self.types.Part(text=user_query)])
                ],
                config=self.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    temperature=0.1
                ),
            )
            
            raw_json = response.text
            if not raw_json:
                raise ValueError("Empty response from Gemini")
            
            # Clean up the JSON response - sometimes Gemini adds extra formatting
            raw_json = raw_json.strip()
            if raw_json.startswith('```json'):
                raw_json = raw_json[7:]
            if raw_json.endswith('```'):
                raw_json = raw_json[:-3]
            raw_json = raw_json.strip()
            
            result = json.loads(raw_json)
            logger.debug(f"Gemini response: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            # Return a fallback response instead of raising
            return {
                "audit_type": "api_error",
                "commands": [],
                "parameters": {},
                "description": f"AI service error: {str(e)}",
                "error": f"Gemini API error: {e}"
            }


class AIService:
    """
    Main AI service that handles provider selection and command generation
    """
    
    def __init__(self, provider: str = 'openai'):
        self.provider_name = provider
        
        if provider == 'openai':
            self.provider = OpenAIProvider()
        elif provider == 'gemini':
            self.provider = GeminiProvider()
        else:
            raise ValueError(f"Unsupported AI provider: {provider}")
        
        logger.info(f"AI Service initialized with provider: {provider}")
    
    def generate_audit_commands(self, user_query: str) -> Dict[str, Any]:
        """
        Generate audit commands from natural language query
        
        Args:
            user_query: Natural language query from user
            
        Returns:
            Dictionary containing audit type, commands, and parameters
        """
        try:
            logger.info(f"Generating commands for query: {user_query}")
            result = self.provider.generate_commands(user_query)
            
            # Validate response structure
            required_keys = ['audit_type', 'commands', 'parameters', 'description']
            for key in required_keys:
                if key not in result:
                    raise ValueError(f"AI response missing required key: {key}")
            
            logger.info(f"Generated audit type: {result['audit_type']}")
            return result
            
        except Exception as e:
            logger.error(f"Error generating audit commands: {e}")
            raise
