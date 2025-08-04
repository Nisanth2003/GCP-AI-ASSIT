# GCP Security Audit Tool - Local Installation Guide

## Overview
This AI-powered command-line tool performs comprehensive security audits on Google Cloud Platform (GCP) resources using natural language queries.

## Prerequisites

### 1. Python Requirements
- Python 3.11 or higher
- pip package manager

### 2. Required Dependencies
Install the following Python packages:

```bash
pip install click>=8.2.1
pip install google-auth>=2.40.3
pip install google-cloud-billing>=1.16.3
pip install google-cloud-iam>=2.19.1
pip install google-cloud-logging>=3.12.1
pip install google-cloud-resource-manager>=1.14.2
pip install google-cloud-service-usage>=1.13.1
pip install google-genai>=1.27.0
pip install openai>=1.97.1
pip install tabulate>=0.9.0
```

Or install all at once:
```bash
pip install click google-auth google-cloud-billing google-cloud-iam google-cloud-logging google-cloud-resource-manager google-cloud-service-usage google-genai openai tabulate
```

## Setup Instructions

### 1. AI Provider Configuration
You need an API key from either OpenAI or Google Gemini:

**Option A: Using Google Gemini (Recommended)**
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
```

**Option B: Using OpenAI**
```bash
export OPENAI_API_KEY="your_openai_api_key_here"
```

### 2. GCP Credentials (Optional for Demo Mode)
For real GCP audits, set up GCP credentials:

**Option A: Service Account Key**
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/service-account-key.json"
export GCP_PROJECT_ID="your-gcp-project-id"
```

**Option B: Default Application Credentials**
```bash
gcloud auth application-default login
export GCP_PROJECT_ID="your-gcp-project-id"
```

**Demo Mode**: The tool works without GCP credentials using sample data for testing.

## Running the Application

### Interactive Mode (Recommended)
```bash
python main.py
```

This starts an interactive session where you can enter natural language queries.

### Single Query Mode
```bash
# Using Gemini AI
python main.py --ai-provider gemini -q "show me inactive users for 90 days"

# Using OpenAI
python main.py --ai-provider openai -q "check MFA status for users"

# With specific project
python main.py --project your-gcp-project-id -q "list admin policies"
```

### Command Options
- `--query, -q`: Natural language audit query
- `--days, -d`: Number of days for time-based queries (default: 30)
- `--project, -p`: GCP Project ID (overrides environment variable)
- `--format, -f`: Output format (table, json, csv)
- `--ai-provider`: AI provider (openai, gemini)
- `--verbose, -v`: Enable verbose logging

## Example Queries

```bash
# Check for inactive users
python main.py -q "show users who haven't logged in for 60 days"

# MFA status
python main.py -q "list users without MFA enabled"

# Service account key rotation
python main.py -q "check old service account keys"

# Service quotas
python main.py -q "show compute engine quotas"

# Support plan
python main.py -q "what's my GCP support plan"

# Admin policies
python main.py -q "list all admin roles and policies"
```

## Available Audit Types

1. **Inactive Users**: Find users who haven't logged in for X days
2. **MFA Status**: Check users without multi-factor authentication
3. **Key Rotation**: Identify old service account keys
4. **Service Quotas**: View current service limits and usage
5. **Support Plan**: Display GCP support plan details
6. **Admin Policies**: List policies and roles with admin access

## Output Formats

- **Table** (default): Human-readable tabulated output
- **JSON**: Machine-readable JSON format
- **CSV**: Spreadsheet-compatible format

## Demo Mode

If you don't have GCP credentials configured, the tool automatically runs in demo mode with sample data. This is perfect for testing the functionality.

## Troubleshooting

### Common Issues

1. **Missing API Key Error**
   ```
   AI API key is required. Set OPENAI_API_KEY or GEMINI_API_KEY environment variable
   ```
   Solution: Set the appropriate environment variable for your AI provider.

2. **Import Errors**
   ```
   ModuleNotFoundError: No module named 'google.genai'
   ```
   Solution: Install missing dependencies using pip.

3. **GCP Authentication Errors**
   The tool will automatically switch to demo mode if GCP credentials are not available.

### Getting API Keys

**Google Gemini API Key**:
1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Create a new API key
3. Set it as an environment variable

**OpenAI API Key**:
1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Create an API key in your account settings
3. Set it as an environment variable

## Security Notes

- All audit operations are read-only
- The tool validates commands to prevent destructive operations
- Credentials are handled securely through environment variables
- Demo mode provides safe testing without real GCP access

## Support

For issues or questions about the tool, check the logs with the `--verbose` flag for detailed debugging information.


Initially to run this we have to run the following command:
open 2 terminals
1)
->set GEMINI_API_KEY="your gemini api key"
->uvicorn api_server:app --reload --port 8000 

2)
streamlit run app.py 

run these in those terminals now it is ready to use. 

the commands it will work for right now.

Task	Description
1.	List inactive IAM users (no activity in X days)
2.	List users with MFA not enabled
3.	List service accounts with keys not rotated in X days
4.	View current GCP quotas (e.g., Compute, API limits)
5.	View current support plan (Basic, Standard, Enhanced, Premium)
6.	List roles/policies with Admin or overly permissive access