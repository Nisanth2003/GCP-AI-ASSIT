"""
Core audit functions for GCP security compliance checking
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from gcp_connector import GCPConnector

logger = logging.getLogger(__name__)


class AuditFunctions:
    """
    Implements the core audit functions for GCP security compliance
    """
    
    def __init__(self, gcp_connector: GCPConnector, default_days: int = 30):
        self.gcp = gcp_connector
        self.default_days = default_days
        logger.info("Audit functions initialized")
    
    def check_inactive_users(self, days: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Check for inactive users who haven't logged in for X days
        Uses Cloud Audit Logs to find login activities
        """
        days = days or self.default_days
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        logger.info(f"Checking for users inactive for {days} days (since {cutoff_date.isoformat()})")
        
        try:
            # Query for authentication events in audit logs
            auth_filter = f'''
                protoPayload.serviceName="login.googleapis.com"
                AND protoPayload.methodName="google.login.LoginService.loginSuccess"
                AND timestamp >= "{cutoff_date.isoformat()}Z"
            '''
            
            recent_logins = self.gcp.query_audit_logs(auth_filter, limit=5000)
            
            # Extract users who have logged in recently
            active_users = set()
            for entry in recent_logins:
                if 'proto_payload' in entry and entry['proto_payload']:
                    auth_info = entry['proto_payload'].get('authenticationInfo', {})
                    principal_email = auth_info.get('principalEmail')
                    if principal_email:
                        active_users.add(principal_email)
            
            # Get all users from IAM policy
            iam_policy = self.gcp.get_project_iam_policy()
            all_users = set()
            
            for binding in iam_policy['bindings']:
                for member in binding['members']:
                    if member.startswith('user:'):
                        all_users.add(member[5:])  # Remove 'user:' prefix
            
            # Find inactive users
            inactive_users = all_users - active_users
            
            result = {
                'total_users': len(all_users),
                'active_users': len(active_users),
                'inactive_users': len(inactive_users),
                'inactive_user_list': list(inactive_users),
                'days_threshold': days,
                'scan_date': datetime.utcnow().isoformat(),
                'active_user_list': list(active_users)
            }
            
            logger.info(f"Found {len(inactive_users)} inactive users out of {len(all_users)} total users")
            return result
            
        except Exception as e:
            logger.error(f"Error checking inactive users: {e}")
            raise
    
    def check_mfa_status(self, **kwargs) -> Dict[str, Any]:
        """
        Check MFA status for users
        Note: Direct MFA status checking requires Admin SDK which may not be available
        This provides information about 2-step verification policies
        """
        logger.info("Checking MFA status for users")
        
        try:
            # Get IAM policy to identify users
            iam_policy = self.gcp.get_project_iam_policy()
            all_users = set()
            
            for binding in iam_policy['bindings']:
                for member in binding['members']:
                    if member.startswith('user:'):
                        all_users.add(member[5:])
            
            # Query audit logs for MFA-related events
            mfa_filter = '''
                (protoPayload.serviceName="login.googleapis.com" 
                AND protoPayload.methodName="google.login.LoginService.loginSuccess"
                AND protoPayload.authenticationInfo.secondFactorType!="")
                OR
                (protoPayload.serviceName="admin.googleapis.com"
                AND protoPayload.methodName="admin.AdminService.changeUserTwoStepVerification")
            '''
            
            mfa_events = self.gcp.query_audit_logs(mfa_filter, limit=1000)
            
            # Extract users with MFA activity
            users_with_mfa_activity = set()
            for entry in mfa_events:
                if 'proto_payload' in entry and entry['proto_payload']:
                    auth_info = entry['proto_payload'].get('authenticationInfo', {})
                    principal_email = auth_info.get('principalEmail')
                    if principal_email:
                        users_with_mfa_activity.add(principal_email)
            
            # Users without recent MFA activity (potential MFA not enabled)
            users_without_mfa_activity = all_users - users_with_mfa_activity
            
            result = {
                'total_users': len(all_users),
                'users_with_mfa_activity': len(users_with_mfa_activity),
                'users_without_mfa_activity': len(users_without_mfa_activity),
                'users_with_mfa_list': list(users_with_mfa_activity),
                'users_without_mfa_list': list(users_without_mfa_activity),
                'scan_date': datetime.utcnow().isoformat(),
                'note': 'This shows MFA activity in audit logs. Users without activity may not have MFA enabled or may not have logged in recently.'
            }
            
            logger.info(f"Found {len(users_without_mfa_activity)} users without recent MFA activity")
            return result
            
        except Exception as e:
            logger.error(f"Error checking MFA status: {e}")
            raise
    
    def check_key_rotation(self, days: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Check service account keys that haven't been rotated in X days
        """
        days = days or self.default_days
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        logger.info(f"Checking for service account keys not rotated in {days} days")
        
        try:
            # Get all service accounts
            service_accounts = self.gcp.list_service_accounts()
            
            old_keys = []
            total_keys = 0
            
            for sa in service_accounts:
                # Get keys for each service account
                keys = self.gcp.list_service_account_keys(sa['email'])
                
                for key in keys:
                    total_keys += 1
                    
                    # Check if key is older than threshold
                    if key['valid_after_time'] and key['valid_after_time'] < cutoff_date:
                        old_keys.append({
                            'service_account': sa['email'],
                            'service_account_name': sa['display_name'],
                            'key_name': key['name'],
                            'key_type': key['key_type'],
                            'created_date': key['valid_after_time'].isoformat() if key['valid_after_time'] else None,
                            'age_days': (datetime.utcnow() - key['valid_after_time']).days if key['valid_after_time'] else None,
                            'disabled': key['disabled']
                        })
            
            result = {
                'total_service_accounts': len(service_accounts),
                'total_keys': total_keys,
                'old_keys_count': len(old_keys),
                'old_keys': old_keys,
                'days_threshold': days,
                'scan_date': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Found {len(old_keys)} old keys out of {total_keys} total keys")
            return result
            
        except Exception as e:
            logger.error(f"Error checking key rotation: {e}")
            raise
    
    def get_service_quotas(self, service_name: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Get current service limits and quotas
        """
        logger.info(f"Getting service quotas for: {service_name or 'all services'}")
        
        try:
            quotas = self.gcp.get_service_quotas(service_name)
            enabled_services = self.gcp.list_enabled_services()
            
            # Organize quotas by service
            quotas_by_service = {}
            for quota in quotas:
                service = quota['name'].split('/')[1] if '/' in quota['name'] else 'unknown'
                if service not in quotas_by_service:
                    quotas_by_service[service] = []
                quotas_by_service[service].append(quota)
            
            result = {
                'total_quota_metrics': len(quotas),
                'services_with_quotas': len(quotas_by_service),
                'enabled_services_count': len(enabled_services),
                'quotas_by_service': quotas_by_service,
                'enabled_services': enabled_services,
                'scan_date': datetime.utcnow().isoformat()
            }
            
            if service_name:
                result['filtered_service'] = service_name
            
            logger.info(f"Retrieved quotas for {len(quotas_by_service)} services")
            return result
            
        except Exception as e:
            logger.error(f"Error getting service quotas: {e}")
            raise
    
    def get_support_plan(self, **kwargs) -> Dict[str, Any]:
        """
        Get GCP support plan details and billing information
        """
        logger.info("Getting support plan and billing information")
        
        try:
            billing_info = self.gcp.get_billing_info()
            
            # Determine support level based on billing account
            support_level = "Basic (Free)"
            if billing_info['project_billing_info'] and billing_info['project_billing_info']['billing_enabled']:
                support_level = "Standard (Paid billing account)"
                
                # Check for enterprise indicators
                if billing_info['billing_accounts']:
                    for account in billing_info['billing_accounts']:
                        if account.get('master_billing_account'):
                            support_level = "Enterprise (Organization billing)"
                            break
            
            result = {
                'support_level': support_level,
                'billing_enabled': billing_info['project_billing_info']['billing_enabled'] if billing_info['project_billing_info'] else False,
                'billing_accounts': billing_info['billing_accounts'],
                'project_billing_info': billing_info['project_billing_info'],
                'scan_date': datetime.utcnow().isoformat(),
                'note': 'GCP support levels: Basic (free), Standard (with billing), Enterprise (organization-level billing)'
            }
            
            logger.info(f"Support level determined as: {support_level}")
            return result
            
        except Exception as e:
            logger.error(f"Error getting support plan: {e}")
            raise
    
    def list_admin_policies(self, **kwargs) -> Dict[str, Any]:
        """
        List all policies and roles with Administrator access
        """
        logger.info("Listing admin policies and roles")
        
        try:
            # Get IAM policy for the project
            iam_policy = self.gcp.get_project_iam_policy()
            
            # Define admin roles (roles that grant administrative access)
            admin_roles = {
                'roles/owner': 'Owner (Full administrative access)',
                'roles/editor': 'Editor (Can modify resources)',
                'roles/iam.securityAdmin': 'Security Admin (IAM administration)',
                'roles/iam.organizationRoleAdmin': 'Organization Role Admin',
                'roles/resourcemanager.organizationAdmin': 'Organization Admin',
                'roles/resourcemanager.projectIamAdmin': 'Project IAM Admin',
                'roles/compute.admin': 'Compute Admin',
                'roles/storage.admin': 'Storage Admin',
                'roles/billing.admin': 'Billing Admin'
            }
            
            admin_bindings = []
            admin_members = set()
            
            for binding in iam_policy['bindings']:
                role = binding['role']
                
                # Check if this is an admin role or custom role with admin permissions
                is_admin_role = (
                    role in admin_roles or
                    'admin' in role.lower() or
                    role == 'roles/owner' or
                    role == 'roles/editor'
                )
                
                if is_admin_role:
                    admin_bindings.append({
                        'role': role,
                        'role_description': admin_roles.get(role, 'Administrative role'),
                        'members': binding['members'],
                        'member_count': len(binding['members']),
                        'condition': binding['condition']
                    })
                    
                    # Collect all admin members
                    admin_members.update(binding['members'])
            
            # Categorize admin members
            admin_users = [m for m in admin_members if m.startswith('user:')]
            admin_service_accounts = [m for m in admin_members if m.startswith('serviceAccount:')]
            admin_groups = [m for m in admin_members if m.startswith('group:')]
            admin_domains = [m for m in admin_members if m.startswith('domain:')]
            
            result = {
                'total_admin_bindings': len(admin_bindings),
                'total_admin_members': len(admin_members),
                'admin_bindings': admin_bindings,
                'admin_members_by_type': {
                    'users': admin_users,
                    'service_accounts': admin_service_accounts,
                    'groups': admin_groups,
                    'domains': admin_domains
                },
                'admin_member_counts': {
                    'users': len(admin_users),
                    'service_accounts': len(admin_service_accounts),
                    'groups': len(admin_groups),
                    'domains': len(admin_domains)
                },
                'scan_date': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Found {len(admin_bindings)} admin role bindings with {len(admin_members)} total admin members")
            return result
            
        except Exception as e:
            logger.error(f"Error listing admin policies: {e}")
            raise
