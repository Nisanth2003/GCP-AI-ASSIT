"""
Response formatting and output generation for audit results
"""

import json
import csv
import io
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from tabulate import tabulate

logger = logging.getLogger(__name__)


class ResponseFormatter:
    """
    Formats audit results into human-readable outputs in various formats
    """
    
    def __init__(self):
        self.format_handlers = {
            'table': self._format_as_table,
            'json': self._format_as_json,
            'csv': self._format_as_csv
        }
        logger.info("Response formatter initialized")
    
    def format_audit_result(self, audit_type: str, data: Dict[str, Any], 
                          format: str = 'table', query: str = '') -> str:
        """
        Format audit results based on type and requested format
        
        Args:
            audit_type: Type of audit performed
            data: Raw audit data
            format: Output format (table, json, csv)
            query: Original user query
            
        Returns:
            Formatted string output
        """
        try:
            # Add metadata
            formatted_data = {
                'audit_type': audit_type,
                'query': query,
                'timestamp': datetime.utcnow().isoformat(),
                'data': data
            }
            
            if format not in self.format_handlers:
                format = 'table'  # Default fallback
            
            handler = self.format_handlers[format]
            return handler(audit_type, formatted_data)
            
        except Exception as e:
            logger.error(f"Error formatting audit result: {e}")
            return f"❌ Error formatting results: {e}"
    
    def _format_as_table(self, audit_type: str, formatted_data: Dict[str, Any]) -> str:
        """
        Format results as human-readable tables
        """
        data = formatted_data['data']
        output = []
        
        # Header
        output.append("🔍 GCP Security Audit Report")
        output.append("=" * 50)
        output.append(f"Audit Type: {audit_type.replace('_', ' ').title()}")
        output.append(f"Query: {formatted_data['query']}")
        output.append(f"Timestamp: {formatted_data['timestamp']}")
        output.append("")
        
        # Format based on audit type
        if audit_type == 'inactive_users':
            output.extend(self._format_inactive_users_table(data))
        elif audit_type == 'mfa_status':
            output.extend(self._format_mfa_status_table(data))
        elif audit_type == 'key_rotation':
            output.extend(self._format_key_rotation_table(data))
        elif audit_type == 'service_quotas':
            output.extend(self._format_service_quotas_table(data))
        elif audit_type == 'support_plan':
            output.extend(self._format_support_plan_table(data))
        elif audit_type == 'admin_policies':
            output.extend(self._format_admin_policies_table(data))
        else:
            output.append("Unknown audit type")
        
        return '\n'.join(output)
    
    def _format_inactive_users_table(self, data: Dict[str, Any]) -> List[str]:
        """Format inactive users data as table"""
        output = []
        
        # Summary
        output.append("📊 Summary:")
        summary_data = [
            ["Total Users", data['total_users']],
            ["Active Users", data['active_users']],
            ["Inactive Users", data['inactive_users']],
            ["Days Threshold", data['days_threshold']]
        ]
        output.append(tabulate(summary_data, headers=["Metric", "Count"], tablefmt="grid"))
        output.append("")
        
        # Inactive users list
        if data['inactive_user_list']:
            output.append("⚠️  Inactive Users:")
            inactive_table = [[i+1, user] for i, user in enumerate(data['inactive_user_list'])]
            output.append(tabulate(inactive_table, headers=["#", "User Email"], tablefmt="grid"))
        else:
            output.append("✅ No inactive users found!")
        
        return output
    
    def _format_mfa_status_table(self, data: Dict[str, Any]) -> List[str]:
        """Format MFA status data as table"""
        output = []
        
        # Summary
        output.append("📊 MFA Status Summary:")
        summary_data = [
            ["Total Users", data['total_users']],
            ["Users with MFA Activity", data['users_with_mfa_activity']],
            ["Users without MFA Activity", data['users_without_mfa_activity']]
        ]
        output.append(tabulate(summary_data, headers=["Metric", "Count"], tablefmt="grid"))
        output.append("")
        output.append(f"ℹ️  Note: {data['note']}")
        output.append("")
        
        # Users without MFA activity
        if data['users_without_mfa_list']:
            output.append("⚠️  Users without Recent MFA Activity:")
            mfa_table = [[i+1, user] for i, user in enumerate(data['users_without_mfa_list'])]
            output.append(tabulate(mfa_table, headers=["#", "User Email"], tablefmt="grid"))
        else:
            output.append("✅ All users have recent MFA activity!")
        
        return output
    
    def _format_key_rotation_table(self, data: Dict[str, Any]) -> List[str]:
        """Format key rotation data as table"""
        output = []
        
        # Summary
        output.append("📊 Service Account Key Rotation Summary:")
        summary_data = [
            ["Total Service Accounts", data['total_service_accounts']],
            ["Total Keys", data['total_keys']],
            ["Old Keys (need rotation)", data['old_keys_count']],
            ["Days Threshold", data['days_threshold']]
        ]
        output.append(tabulate(summary_data, headers=["Metric", "Count"], tablefmt="grid"))
        output.append("")
        
        # Old keys details
        if data['old_keys']:
            output.append("⚠️  Keys Requiring Rotation:")
            key_table = []
            for key in data['old_keys']:
                key_table.append([
                    key['service_account'],
                    key['key_type'],
                    key['created_date'][:10] if key['created_date'] else 'Unknown',
                    key['age_days'],
                    "Yes" if key['disabled'] else "No"
                ])
            
            headers = ["Service Account", "Key Type", "Created Date", "Age (Days)", "Disabled"]
            output.append(tabulate(key_table, headers=headers, tablefmt="grid"))
        else:
            output.append("✅ All keys are within rotation threshold!")
        
        return output
    
    def _format_service_quotas_table(self, data: Dict[str, Any]) -> List[str]:
        """Format service quotas data as table"""
        output = []
        
        # Summary
        output.append("📊 Service Quotas Summary:")
        summary_data = [
            ["Total Quota Metrics", data['total_quota_metrics']],
            ["Services with Quotas", data['services_with_quotas']],
            ["Enabled Services", data['enabled_services_count']]
        ]
        output.append(tabulate(summary_data, headers=["Metric", "Count"], tablefmt="grid"))
        output.append("")
        
        # Top services by quota count
        if data['quotas_by_service']:
            output.append("🔧 Top Services by Quota Metrics:")
            service_counts = [(service, len(quotas)) for service, quotas in data['quotas_by_service'].items()]
            service_counts.sort(key=lambda x: x[1], reverse=True)
            
            top_services = service_counts[:10]  # Top 10
            service_table = [[service, count] for service, count in top_services]
            output.append(tabulate(service_table, headers=["Service", "Quota Metrics"], tablefmt="grid"))
        
        return output
    
    def _format_support_plan_table(self, data: Dict[str, Any]) -> List[str]:
        """Format support plan data as table"""
        output = []
        
        # Support info
        output.append("📞 GCP Support Plan Information:")
        support_data = [
            ["Support Level", data['support_level']],
            ["Billing Enabled", "Yes" if data['billing_enabled'] else "No"],
            ["Billing Accounts", len(data['billing_accounts'])]
        ]
        output.append(tabulate(support_data, headers=["Attribute", "Value"], tablefmt="grid"))
        output.append("")
        
        # Billing accounts
        if data['billing_accounts']:
            output.append("💳 Billing Accounts:")
            billing_table = []
            for account in data['billing_accounts']:
                billing_table.append([
                    account['display_name'],
                    "Open" if account['open'] else "Closed",
                    "Yes" if account.get('master_billing_account') else "No"
                ])
            
            headers = ["Account Name", "Status", "Master Account"]
            output.append(tabulate(billing_table, headers=headers, tablefmt="grid"))
        
        output.append("")
        output.append(f"ℹ️  Note: {data['note']}")
        
        return output
    
    def _format_admin_policies_table(self, data: Dict[str, Any]) -> List[str]:
        """Format admin policies data as table"""
        output = []
        
        # Summary
        output.append("👑 Administrator Access Summary:")
        summary_data = [
            ["Admin Role Bindings", data['total_admin_bindings']],
            ["Total Admin Members", data['total_admin_members']],
            ["Admin Users", data['admin_member_counts']['users']],
            ["Admin Service Accounts", data['admin_member_counts']['service_accounts']],
            ["Admin Groups", data['admin_member_counts']['groups']]
        ]
        output.append(tabulate(summary_data, headers=["Metric", "Count"], tablefmt="grid"))
        output.append("")
        
        # Admin role bindings
        if data['admin_bindings']:
            output.append("🔐 Administrative Role Bindings:")
            binding_table = []
            for binding in data['admin_bindings']:
                binding_table.append([
                    binding['role'],
                    binding['member_count'],
                    ', '.join(binding['members'][:3]) + ('...' if len(binding['members']) > 3 else '')
                ])
            
            headers = ["Role", "Members", "Sample Members"]
            output.append(tabulate(binding_table, headers=headers, tablefmt="grid"))
        
        return output
    
    def _format_as_json(self, audit_type: str, formatted_data: Dict[str, Any]) -> str:
        """Format results as JSON"""
        return json.dumps(formatted_data, indent=2, default=str)
    
    def _format_as_csv(self, audit_type: str, formatted_data: Dict[str, Any]) -> str:
        """Format results as CSV"""
        data = formatted_data['data']
        output = io.StringIO()
        
        if audit_type == 'inactive_users' and data['inactive_user_list']:
            writer = csv.writer(output)
            writer.writerow(['User Email', 'Status', 'Days Threshold'])
            for user in data['inactive_user_list']:
                writer.writerow([user, 'Inactive', data['days_threshold']])
        
        elif audit_type == 'key_rotation' and data['old_keys']:
            writer = csv.writer(output)
            writer.writerow(['Service Account', 'Key Type', 'Created Date', 'Age Days', 'Disabled'])
            for key in data['old_keys']:
                writer.writerow([
                    key['service_account'], 
                    key['key_type'], 
                    key['created_date'],
                    key['age_days'],
                    key['disabled']
                ])
        
        elif audit_type == 'admin_policies' and data['admin_bindings']:
            writer = csv.writer(output)
            writer.writerow(['Role', 'Member', 'Role Description'])
            for binding in data['admin_bindings']:
                for member in binding['members']:
                    writer.writerow([binding['role'], member, binding['role_description']])
        
        else:
            # Fallback: convert to simple key-value CSV
            writer = csv.writer(output)
            writer.writerow(['Key', 'Value'])
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)):
                    writer.writerow([key, value])
        
        return output.getvalue()
