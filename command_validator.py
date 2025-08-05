"""
Command validation and security controls for GCP audit operations
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class CommandValidator:
    """
    Validates generated commands against security policies and whitelists
    """
    
    def __init__(self):
        # Whitelist of allowed GCP operations (expanded for better coverage)
        self.allowed_gcloud_commands = {
            # IAM operations (read-only)
            'gcloud iam service-accounts list',
            'gcloud iam service-accounts keys list',
            'gcloud iam roles list',
            'gcloud iam service-accounts get-iam-policy',
            'gcloud projects get-iam-policy',
            'gcloud organizations get-iam-policy',
            'gcloud alpha identity users list',
            
            # Logging operations (read-only)
            'gcloud logging read',
            'gcloud logging logs list',
            'gcloud logging sinks list',
            
            # Resource manager operations (read-only)
            'gcloud projects list',
            'gcloud projects describe',
            'gcloud organizations list',
            
            # Service usage operations (read-only)
            'gcloud services list',
            'gcloud services list --enabled',
            'gcloud compute quotas list',
            'gcloud services quota list',
            
            # Billing operations (read-only)
            'gcloud billing accounts list',
            'gcloud billing projects list',
            'gcloud billing accounts get-iam-policy',
            'gcloud support plans describe',
        }
        
        # Allowed API patterns
        self.allowed_api_patterns = [
            r'iam\.googleapis\.com.*list.*',
            r'iam\.googleapis\.com.*get.*',
            r'logging\.googleapis\.com.*list.*',
            r'logging\.googleapis\.com.*entries:list',
            r'cloudresourcemanager\.googleapis\.com.*list.*',
            r'cloudresourcemanager\.googleapis\.com.*get.*',
            r'serviceusage\.googleapis\.com.*list.*',
            r'cloudbilling\.googleapis\.com.*list.*',
            r'compute\.googleapis\.com.*list.*',
        ]
        
        # Dangerous operations that should never be allowed
        self.forbidden_operations = [
            'set-iam-policy', 'add-iam-policy-binding', 'remove-iam-policy-binding',
            'delete-', 'remove-', 'modify-', 'update-',
            'enable-', 'disable-', 'start-', 'stop-', 'reset-', 'restart-'
        ]
        
        logger.info("Command validator initialized with security policies")
    
    def validate_commands(self, commands: List[str]) -> bool:
        """
        Validate a list of commands against security policies
        
        Args:
            commands: List of commands to validate
            
        Returns:
            True if all commands are safe, False otherwise
        """
        if not commands:
            logger.warning("No commands to validate")
            return False
        
        for command in commands:
            if not self._validate_single_command(command):
                logger.error(f"Command failed validation: {command}")
                return False
        
        logger.info(f"All {len(commands)} commands passed validation")
        return True
    
    def _validate_single_command(self, command: str) -> bool:
        """
        Validate a single command
        
        Args:
            command: Command string to validate
            
        Returns:
            True if command is safe, False otherwise
        """
        command_lower = command.lower().strip()
        
        # Remove placeholder patterns before validation
        command_lower = self._clean_placeholders(command_lower)
        
        # Check for forbidden operations
        for forbidden in self.forbidden_operations:
            if forbidden in command_lower:
                logger.warning(f"Forbidden operation detected: {forbidden} in {command}")
                return False
        
        # Check if it's a whitelisted gcloud command
        if command_lower.startswith('gcloud'):
            return self._validate_gcloud_command(command_lower)
        
        # Check if it's an allowed API call pattern
        if 'googleapis.com' in command_lower:
            return self._validate_api_call(command_lower)
        
        # Check if it's a recognized audit function call
        if self._is_audit_function_call(command):
            return True
        
        # Allow common safe command patterns that AI might suggest
        safe_patterns = [
            'check_inactive_users', 'check_mfa_status', 'check_key_rotation',
            'get_service_quotas', 'get_support_plan', 'list_admin_policies',
            'query audit logs', 'list service accounts', 'get iam policy'
        ]
        
        command_lower = command.lower()
        for pattern in safe_patterns:
            if pattern in command_lower:
                return True
        
        logger.warning(f"Command not in whitelist: {command}")
        return False
    
    def _clean_placeholders(self, command: str) -> str:
        """
        Remove common placeholder patterns that might confuse validation
        """
        # Common placeholder patterns to remove/replace
        placeholders = [
            ('organization_id', 'test-org'),
            ('your_organization_id', 'test-org'),
            ('<your_organization_id>', 'test-org'),
            ('<organization_id>', 'test-org'),
            ('<project-id>', 'test-project'),
            ('<your-project-id>', 'test-project'),
            ('your_billing_account_id', 'test-billing'),
            ('<billing_account_id>', 'test-billing')
        ]
        
        cleaned_command = command
        for placeholder, replacement in placeholders:
            cleaned_command = cleaned_command.replace(placeholder, replacement)
        
        return cleaned_command
    
    def _validate_gcloud_command(self, command: str) -> bool:
        """
        Validate gcloud command against whitelist
        """
        # Extract base command (without parameters and flags)
        command_parts = command.split()
        if len(command_parts) < 3:
            return False
            
        # Build base command pattern
        base_patterns = [
            'gcloud iam service-accounts list',
            'gcloud iam service-accounts keys list', 
            'gcloud iam roles list',
            'gcloud projects get-iam-policy',
            'gcloud organizations get-iam-policy',
            'gcloud logging read',
            'gcloud services list',
            'gcloud services quota list',
            'gcloud billing accounts list',
            'gcloud billing accounts get-iam-policy',
            'gcloud support plans describe',
            'gcloud support organizations describe',
            'gcloud alpha identity users list',
            'gcloud compute quotas list',
            'gcloud compute project-info describe'
        ]
        
        # Check if the command matches any allowed pattern (ignoring extra flags and parameters)
        for pattern in base_patterns:
            pattern_parts = pattern.split()
            if (len(command_parts) >= len(pattern_parts) and 
                command_parts[:len(pattern_parts)] == pattern_parts):
                return True
        
        return False
    
    def _validate_api_call(self, command: str) -> bool:
        """
        Validate API call against allowed patterns
        """
        for pattern in self.allowed_api_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        
        return False
    
    def _is_audit_function_call(self, command: str) -> bool:
        """
        Check if command is a recognized audit function call
        """
        audit_functions = [
            'check_inactive_users',
            'check_mfa_status', 
            'check_key_rotation',
            'get_service_quotas',
            'get_support_plan',
            'list_admin_policies'
        ]
        
        return any(func in command for func in audit_functions)
    
    def validate_audit_type(self, audit_type: str) -> bool:
        """
        Validate that the audit type is recognized and allowed
        
        Args:
            audit_type: The audit type to validate
            
        Returns:
            True if audit type is valid, False otherwise
        """
        valid_audit_types = {
            'inactive_users',
            'mfa_status', 
            'key_rotation',
            'service_quotas',
            'support_plan',
            'admin_policies'
        }
        
        is_valid = audit_type in valid_audit_types
        if not is_valid:
            logger.warning(f"Invalid audit type: {audit_type}")
        
        return is_valid
    
    def sanitize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize and validate parameters for audit functions
        
        Args:
            parameters: Dictionary of parameters to sanitize
            
        Returns:
            Sanitized parameters dictionary
        """
        sanitized = {}
        
        for key, value in parameters.items():
            # Convert to string and remove potentially dangerous characters
            sanitized_key = re.sub(r'[^a-zA-Z0-9_]', '', str(key))
            
            if isinstance(value, (int, float)):
                # Validate numeric values are within reasonable ranges
                if key == 'days' and (value < 1 or value > 3650):  # Max 10 years
                    sanitized[sanitized_key] = 30  # Default to 30 days
                else:
                    sanitized[sanitized_key] = value
            elif isinstance(value, str):
                # Sanitize string values
                sanitized_value = re.sub(r'[<>"\';\\]', '', str(value))[:100]  # Limit length
                sanitized[sanitized_key] = sanitized_value
            elif isinstance(value, bool):
                sanitized[sanitized_key] = value
            else:
                logger.warning(f"Skipping parameter with unsupported type: {key}")
        
        return sanitized
