"""
GCP API connector for executing audit operations
"""

import logging
from typing import Dict, List, Any, Optional
from google.cloud import resourcemanager
from google.cloud import iam
from google.cloud import logging as cloud_logging
from google.cloud import service_usage
from google.cloud import billing
from google.oauth2 import service_account
import os

logger = logging.getLogger(__name__)


class GCPConnector:
    """
    Handles connections and operations with Google Cloud Platform APIs
    """
    
    def __init__(self, config):
        self.config = config
        self.project_id = config.project_id
        
        # Check if this is demo mode
        self.is_demo_mode = self.project_id == "demo-project-12345"
        
        if not self.is_demo_mode:
            # Initialize credentials
            self.credentials = self._get_credentials()
            
            # Initialize API clients
            self._init_clients()
        else:
            logger.info("Running in demo mode - API calls will return sample data")
            # Initialize placeholder clients for demo mode
            self.service_usage_client = None
            self.billing_client = None
        
        logger.info(f"GCP Connector initialized for project: {self.project_id}")
    
    def _get_credentials(self):
        """
        Get GCP credentials from service account or default credentials
        """
        try:
            if self.config.service_account_path and os.path.exists(self.config.service_account_path):
                credentials = service_account.Credentials.from_service_account_file(
                    self.config.service_account_path
                )
                logger.info("Using service account credentials")
                return credentials
            else:
                # Use default application credentials
                from google.auth import default
                credentials, _ = default()
                logger.info("Using default application credentials")
                return credentials
        except Exception as e:
            logger.error(f"Failed to initialize credentials: {e}")
            raise
    
    def _init_clients(self):
        """
        Initialize GCP API clients
        """
        try:
            # Resource Manager client
            self.resource_manager_client = resourcemanager.ProjectsClient(credentials=self.credentials)
            
            # IAM client
            self.iam_client = iam.IAMClient(credentials=self.credentials)
            
            # Cloud Logging client
            self.logging_client = cloud_logging.Client(credentials=self.credentials, project=self.project_id)
            
            # Service Usage client
            self.service_usage_client = service_usage.ServiceUsageClient(credentials=self.credentials)
            
            # Billing client
            self.billing_client = billing.CloudBillingClient(credentials=self.credentials)
            
            logger.info("All GCP API clients initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize GCP clients: {e}")
            raise
    
    def get_project_iam_policy(self) -> Dict[str, Any]:
        """
        Get IAM policy for the current project
        """
        if self.is_demo_mode:
            return self._get_demo_iam_policy()
        
        try:
            request = resourcemanager.GetIamPolicyRequest(
                resource=f"projects/{self.project_id}"
            )
            policy = self.resource_manager_client.get_iam_policy(request=request)
            
            # Convert to dictionary for easier processing
            policy_dict = {
                'bindings': [],
                'etag': policy.etag,
                'version': policy.version
            }
            
            for binding in policy.bindings:
                policy_dict['bindings'].append({
                    'role': binding.role,
                    'members': list(binding.members),
                    'condition': binding.condition.expression if binding.condition else None
                })
            
            logger.info(f"Retrieved IAM policy with {len(policy_dict['bindings'])} bindings")
            return policy_dict
            
        except Exception as e:
            logger.error(f"Failed to get project IAM policy: {e}")
            raise
    
    def list_service_accounts(self) -> List[Dict[str, Any]]:
        """
        List all service accounts in the project
        """
        if self.is_demo_mode:
            return self._get_demo_service_accounts()
        
        try:
            request = iam.ListServiceAccountsRequest(
                name=f"projects/{self.project_id}"
            )
            
            service_accounts = []
            for account in self.iam_client.list_service_accounts(request=request).accounts:
                service_accounts.append({
                    'name': account.name,
                    'email': account.email,
                    'display_name': account.display_name,
                    'description': account.description,
                    'disabled': account.disabled,
                    'oauth2_client_id': account.oauth2_client_id
                })
            
            logger.info(f"Found {len(service_accounts)} service accounts")
            return service_accounts
            
        except Exception as e:
            logger.error(f"Failed to list service accounts: {e}")
            raise
    
    def list_service_account_keys(self, service_account_email: str) -> List[Dict[str, Any]]:
        """
        List keys for a specific service account
        """
        try:
            request = iam.ListServiceAccountKeysRequest(
                name=f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
            )
            
            keys = []
            for key in self.iam_client.list_service_account_keys(request=request).keys:
                keys.append({
                    'name': key.name,
                    'key_type': key.key_type.name,
                    'key_algorithm': key.key_algorithm.name,
                    'valid_after_time': key.valid_after_time,
                    'valid_before_time': key.valid_before_time,
                    'key_origin': key.key_origin.name,
                    'disabled': key.disabled
                })
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to list keys for {service_account_email}: {e}")
            return []
    
    def query_audit_logs(self, filter_query: str, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Query Cloud Audit Logs
        """
        if self.is_demo_mode:
            return self._get_demo_audit_logs(filter_query)
        
        try:
            entries = []
            
            # Query logs with the provided filter
            for entry in self.logging_client.list_entries(
                filter_=filter_query,
                page_size=limit
            ):
                entries.append({
                    'timestamp': entry.timestamp,
                    'log_name': entry.log_name,
                    'resource': dict(entry.resource),
                    'severity': entry.severity.name if entry.severity else None,
                    'labels': dict(entry.labels),
                    'proto_payload': dict(entry.proto_payload) if entry.proto_payload else None
                })
            
            logger.info(f"Retrieved {len(entries)} audit log entries")
            return entries
            
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            raise
    
    def get_service_quotas(self, service_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get service quotas and limits
        """
        if self.is_demo_mode:
            return self._get_demo_service_quotas(service_name)
        
        try:
            parent = f"projects/{self.project_id}"
            request = service_usage.ListServicesRequest(
                parent=parent,
                filter="state:ENABLED"
            )
            
            quotas = []
            # Note: Using list_services instead of quota metrics for simpler implementation
            for service in self.service_usage_client.list_services(request=request):
                if service_name and service_name not in service.name:
                    continue
                
                quotas.append({
                    'name': service.name,
                    'title': service.config.title if service.config else 'Unknown',
                    'state': service.state.name if service.state else 'Unknown',
                    'parent': service.parent
                })
            
            logger.info(f"Retrieved {len(quotas)} service quotas")
            return quotas
            
        except Exception as e:
            logger.error(f"Failed to get service quotas: {e}")
            raise
    
    def get_billing_info(self) -> Dict[str, Any]:
        """
        Get billing account information and support plan details
        """
        if self.is_demo_mode:
            return self._get_demo_billing_info()
        
        try:
            # List billing accounts
            accounts = []
            for account in self.billing_client.list_billing_accounts():
                accounts.append({
                    'name': account.name,
                    'display_name': account.display_name,
                    'open': account.open,
                    'master_billing_account': account.master_billing_account
                })
            
            # Get project billing info
            project_billing_info = None
            try:
                project_name = f"projects/{self.project_id}"
                billing_info = self.billing_client.get_project_billing_info(name=project_name)
                project_billing_info = {
                    'name': billing_info.name,
                    'project_id': billing_info.project_id,
                    'billing_account_name': billing_info.billing_account_name,
                    'billing_enabled': billing_info.billing_enabled
                }
            except Exception as e:
                logger.warning(f"Could not retrieve project billing info: {e}")
            
            return {
                'billing_accounts': accounts,
                'project_billing_info': project_billing_info
            }
            
        except Exception as e:
            logger.error(f"Failed to get billing information: {e}")
            raise
    
    def list_enabled_services(self) -> List[Dict[str, Any]]:
        """
        List enabled services in the project
        """
        if self.is_demo_mode:
            return self._get_demo_enabled_services()
        
        try:
            parent = f"projects/{self.project_id}"
            request = service_usage.ListServicesRequest(
                parent=parent,
                filter="state:ENABLED"
            )
            
            services = []
            for service in self.service_usage_client.list_services(request=request):
                services.append({
                    'name': service.name,
                    'config': {
                        'name': service.config.name,
                        'title': service.config.title,
                        'documentation': service.config.documentation.summary if service.config.documentation else None
                    },
                    'state': service.state.name,
                    'parent': service.parent
                })
            
            logger.info(f"Found {len(services)} enabled services")
            return services
            
        except Exception as e:
            logger.error(f"Failed to list enabled services: {e}")
            raise
    
    # Demo data methods for testing without real GCP credentials
    def _get_demo_iam_policy(self) -> Dict[str, Any]:
        """Return demo IAM policy data"""
        from datetime import datetime
        return {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': ['user:admin@company.com', 'user:ceo@company.com'],
                    'condition': None
                },
                {
                    'role': 'roles/editor',
                    'members': ['user:developer@company.com', 'user:devops@company.com'],
                    'condition': None
                },
                {
                    'role': 'roles/viewer',
                    'members': ['user:inactive.user@company.com', 'user:old.account@company.com'],
                    'condition': None
                }
            ],
            'etag': 'demo-etag',
            'version': 1
        }
    
    def _get_demo_service_accounts(self) -> List[Dict[str, Any]]:
        """Return demo service account data"""
        from datetime import datetime, timedelta
        return [
            {
                'name': f'projects/{self.project_id}/serviceAccounts/demo-sa@demo-project.iam.gserviceaccount.com',
                'email': 'demo-sa@demo-project.iam.gserviceaccount.com',
                'display_name': 'Demo Service Account',
                'description': 'Demo service account for testing',
                'disabled': False,
                'oauth2_client_id': '12345'
            },
            {
                'name': f'projects/{self.project_id}/serviceAccounts/old-sa@demo-project.iam.gserviceaccount.com',
                'email': 'old-sa@demo-project.iam.gserviceaccount.com',
                'display_name': 'Old Service Account',
                'description': 'Service account with old keys',
                'disabled': False,
                'oauth2_client_id': '67890'
            }
        ]
    
    def _get_demo_audit_logs(self, filter_query: str) -> List[Dict[str, Any]]:
        """Return demo audit log data"""
        from datetime import datetime, timedelta
        
        # Return different data based on filter
        if 'login.googleapis.com' in filter_query and 'loginSuccess' in filter_query:
            # Recent login data - only some users have logged in recently
            return [
                {
                    'timestamp': datetime.utcnow() - timedelta(days=1),
                    'log_name': 'projects/demo-project/logs/cloudaudit.googleapis.com%2Factivity',
                    'resource': {'type': 'project', 'labels': {'project_id': 'demo-project'}},
                    'severity': 'INFO',
                    'labels': {},
                    'proto_payload': {
                        'serviceName': 'login.googleapis.com',
                        'methodName': 'google.login.LoginService.loginSuccess',
                        'authenticationInfo': {'principalEmail': 'admin@company.com'}
                    }
                },
                {
                    'timestamp': datetime.utcnow() - timedelta(days=2),
                    'log_name': 'projects/demo-project/logs/cloudaudit.googleapis.com%2Factivity',
                    'resource': {'type': 'project', 'labels': {'project_id': 'demo-project'}},
                    'severity': 'INFO',
                    'labels': {},
                    'proto_payload': {
                        'serviceName': 'login.googleapis.com',
                        'methodName': 'google.login.LoginService.loginSuccess',
                        'authenticationInfo': {'principalEmail': 'developer@company.com'}
                    }
                }
            ]
        elif 'secondFactorType' in filter_query:
            # MFA-related logs
            return [
                {
                    'timestamp': datetime.utcnow() - timedelta(days=1),
                    'log_name': 'projects/demo-project/logs/cloudaudit.googleapis.com%2Factivity',
                    'resource': {'type': 'project', 'labels': {'project_id': 'demo-project'}},
                    'severity': 'INFO',
                    'labels': {},
                    'proto_payload': {
                        'serviceName': 'login.googleapis.com',
                        'methodName': 'google.login.LoginService.loginSuccess',
                        'authenticationInfo': {
                            'principalEmail': 'admin@company.com',
                            'secondFactorType': 'TOTP'
                        }
                    }
                }
            ]
        return []
    
    def _get_demo_service_quotas(self, service_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return demo service quota data"""
        quotas = [
            {
                'name': 'projects/demo-project/services/compute.googleapis.com',
                'title': 'Compute Engine API',
                'state': 'ENABLED',
                'parent': 'projects/demo-project'
            },
            {
                'name': 'projects/demo-project/services/storage.googleapis.com',
                'title': 'Cloud Storage JSON API',
                'state': 'ENABLED', 
                'parent': 'projects/demo-project'
            },
            {
                'name': 'projects/demo-project/services/iam.googleapis.com',
                'title': 'Identity and Access Management (IAM) API',
                'state': 'ENABLED',
                'parent': 'projects/demo-project'
            }
        ]
        
        if service_name:
            quotas = [q for q in quotas if service_name in q['name']]
        
        return quotas
    
    def _get_demo_enabled_services(self) -> List[Dict[str, Any]]:
        """Return demo enabled services data"""
        return [
            {
                'name': 'projects/demo-project/services/compute.googleapis.com',
                'config': {
                    'name': 'compute.googleapis.com',
                    'title': 'Compute Engine API',
                    'documentation': 'Manages compute resources'
                },
                'state': 'ENABLED',
                'parent': 'projects/demo-project'
            },
            {
                'name': 'projects/demo-project/services/storage.googleapis.com',
                'config': {
                    'name': 'storage.googleapis.com',
                    'title': 'Cloud Storage JSON API',
                    'documentation': 'Stores and retrieves data'
                },
                'state': 'ENABLED',
                'parent': 'projects/demo-project'
            },
            {
                'name': 'projects/demo-project/services/iam.googleapis.com',
                'config': {
                    'name': 'iam.googleapis.com',
                    'title': 'Identity and Access Management (IAM) API',
                    'documentation': 'Manages authentication and authorization'
                },
                'state': 'ENABLED',
                'parent': 'projects/demo-project'
            }
        ]
    
    def _get_demo_billing_info(self) -> Dict[str, Any]:
        """Return demo billing information"""
        return {
            'billing_accounts': [
                {
                    'name': 'billingAccounts/012345-ABCDEF-GHIJKL',
                    'display_name': 'Demo Billing Account',
                    'open': True,
                    'master_billing_account': None
                }
            ],
            'project_billing_info': {
                'name': f'projects/{self.project_id}/billingInfo',
                'project_id': self.project_id,
                'billing_account_name': 'billingAccounts/012345-ABCDEF-GHIJKL',
                'billing_enabled': True
            }
        }
    
    def list_service_account_keys(self, service_account_email: str) -> List[Dict[str, Any]]:
        """List keys for a specific service account"""
        if self.is_demo_mode:
            from datetime import datetime, timedelta
            
            # Return old keys for demo
            old_date = datetime.utcnow() - timedelta(days=100)
            recent_date = datetime.utcnow() - timedelta(days=10)
            
            if 'old-sa' in service_account_email:
                return [
                    {
                        'name': f'projects/{self.project_id}/serviceAccounts/{service_account_email}/keys/key1',
                        'key_type': 'USER_MANAGED',
                        'key_algorithm': 'KEY_ALG_RSA_2048',
                        'valid_after_time': old_date,
                        'valid_before_time': None,
                        'key_origin': 'GOOGLE_PROVIDED',
                        'disabled': False
                    }
                ]
            else:
                return [
                    {
                        'name': f'projects/{self.project_id}/serviceAccounts/{service_account_email}/keys/key2',
                        'key_type': 'USER_MANAGED', 
                        'key_algorithm': 'KEY_ALG_RSA_2048',
                        'valid_after_time': recent_date,
                        'valid_before_time': None,
                        'key_origin': 'GOOGLE_PROVIDED',
                        'disabled': False
                    }
                ]
        
        try:
            request = iam.ListServiceAccountKeysRequest(
                name=f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
            )
            
            keys = []
            for key in self.iam_client.list_service_account_keys(request=request).keys:
                keys.append({
                    'name': key.name,
                    'key_type': key.key_type.name,
                    'key_algorithm': key.key_algorithm.name,
                    'valid_after_time': key.valid_after_time,
                    'valid_before_time': key.valid_before_time,
                    'key_origin': key.key_origin.name,
                    'disabled': key.disabled
                })
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to list keys for {service_account_email}: {e}")
            return []
