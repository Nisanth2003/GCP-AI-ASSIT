#!/usr/bin/env python3
"""
GCP Security Audit Tool - AI-Powered Command Line Interface
Main entry point for the application
"""

import click
import json
import logging
import sys
from typing import Optional

from config import Config
from ai_service import AIService
from command_validator import CommandValidator
from gcp_connector import GCPConnector
from response_formatter import ResponseFormatter
from audit_functions import AuditFunctions
from utils import setup_logging, validate_gcp_credentials

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)


@click.command()
@click.option('--query', '-q', help='Natural language query for GCP audit')
@click.option('--days', '-d', default=30, help='Number of days for time-based queries (default: 30)')
@click.option('--project', '-p', help='GCP Project ID (overrides config)')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'csv']), default='table', 
              help='Output format (default: table)')
@click.option('--ai-provider', type=click.Choice(['openai', 'gemini']), default='gemini',
              help='AI provider to use (default: gemini)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def main(query: Optional[str], days: int, project: Optional[str], format: str, 
         ai_provider: str, verbose: bool):
    """
    GCP Security Audit Tool - AI-Powered Command Line Interface
    
    Examples:
        python main.py -q "Show me users who haven't logged in for 90 days" -d 90
        python main.py -q "List all users without MFA enabled"
        python main.py -q "Check service quotas for compute engine"
        python main.py -q "Show admin policies and roles"
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize configuration with demo project if none provided
        if not project:
            project = "demo-project-12345"
            click.echo("Using demo project for testing. Use --project flag for your actual GCP project.")
        
        config = Config(project_id=project)
        
        # For demo purposes, skip credential validation if using demo project
        if project != "demo-project-12345":
            if not validate_gcp_credentials(config.service_account_path):
                logger.error("Invalid GCP credentials. Please check your service account key.")
                sys.exit(1)
        
        # Initialize components
        ai_service = AIService(provider=ai_provider)
        validator = CommandValidator()
        gcp_connector = GCPConnector(config)
        formatter = ResponseFormatter()
        audit_functions = AuditFunctions(gcp_connector, days)
        
        # Interactive mode if no query provided
        if not query:
            click.echo("GCP Security Audit Tool")
            click.echo("Enter your audit queries in natural language, or 'exit' to quit.\n")
            
            while True:
                try:
                    query = click.prompt("Audit Query", type=str)
                    if query and query.lower() in ['exit', 'quit', 'q']:
                        break
                    
                    if query:  # Only process non-empty queries
                        result = process_query(query, ai_service, validator, audit_functions, 
                                             formatter, format, days, project)
                        click.echo(result)
                    else:
                        click.echo("Please enter a query or 'exit' to quit.")
                    click.echo()  # Empty line for readability
                    
                except KeyboardInterrupt:
                    click.echo("\nGoodbye!")
                    break
                except Exception as e:
                    logger.error(f"Error processing query: {e}")
                    click.echo(f"Error: {e}")
        else:
            # Single query mode
            result = process_query(query, ai_service, validator, audit_functions, 
                                 formatter, format, days, project)
            click.echo(result)
            
    except Exception as e:
        logger.error(f"Application error: {e}")
        click.echo(f"Fatal error: {e}")
        sys.exit(1)


def process_query(query: str, ai_service: AIService, validator: CommandValidator,
                 audit_functions: AuditFunctions, formatter: ResponseFormatter,
                 output_format: str, days: int, project_id: str) -> str:
    """
    Process a single audit query through the complete pipeline
    """
    try:
        # Step 1: Get AI-generated commands
        logger.info(f"Processing query: {query}")
        ai_response = ai_service.generate_audit_commands(query)
        
        # Check for errors in AI response
        if 'error' in ai_response:
            if ai_response['audit_type'] == 'invalid_query':
                return "❌ Sorry, I can only help with GCP security audits. Please ask about:\n- Inactive users\n- MFA status\n- Service account key rotation\n- Service quotas and limits\n- Support plan details\n- Admin policies and roles"
            elif ai_response['audit_type'] == 'api_error':
                return f"❌ AI service error: {ai_response['error']}"
        
        # Step 2: Validate commands (skip in demo mode for better user experience)
        if not project_id.startswith("demo-") and not validator.validate_commands(ai_response.get('commands', [])):
            return "❌ Generated commands failed security validation"
        
        # Step 3: Execute audit function
        audit_type = ai_response.get('audit_type')
        if not audit_type:
            return "❌ Could not determine audit type from query"
        
        if audit_type == 'unsupported_query':
            return "❌ This query doesn't match any supported audit types. Try asking about:\n- Inactive users\n- MFA status\n- Service account key rotation\n- Service quotas\n- Support plan\n- Admin policies"
        
        # Execute the appropriate audit function
        raw_data = execute_audit_function(audit_functions, audit_type, ai_response.get('parameters', {}))
        
        # Step 4: Format response
        formatted_result = formatter.format_audit_result(
            audit_type=audit_type,
            data=raw_data,
            format=output_format,
            query=query
        )
        
        return formatted_result
        
    except Exception as e:
        logger.error(f"Error in query processing pipeline: {e}")
        return f"❌ Processing error: {e}"


def execute_audit_function(audit_functions: AuditFunctions, audit_type: str, parameters: dict):
    """
    Route the audit request to the appropriate function
    """
    # Convert string parameters to appropriate types
    processed_params = {}
    for key, value in parameters.items():
        if key == 'days' and isinstance(value, str):
            try:
                processed_params[key] = int(value)
            except (ValueError, TypeError):
                processed_params[key] = 30  # Default fallback
        else:
            processed_params[key] = value
    
    function_map = {
        'inactive_users': audit_functions.check_inactive_users,
        'mfa_status': audit_functions.check_mfa_status,
        'key_rotation': audit_functions.check_key_rotation,
        'service_quotas': audit_functions.get_service_quotas,
        'support_plan': audit_functions.get_support_plan,
        'admin_policies': audit_functions.list_admin_policies
    }
    
    if audit_type not in function_map:
        raise ValueError(f"Unknown audit type: {audit_type}")
    
    return function_map[audit_type](**processed_params)


if __name__ == '__main__':
    main()
