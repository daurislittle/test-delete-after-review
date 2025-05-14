import os
import json
import boto3
import logging
import re
import time
import functools
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, EndpointConnectionError
from typing import Dict, List, Any, Optional, Union, Tuple

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants for subscription states
class SubscriptionState:
    PENDING_CONFIRMATION = "PENDING_CONFIRMATION"
    CONFIRMED = "CONFIRMED"
    CONFIRMATION_EXPIRED = "CONFIRMATION_EXPIRED"
    MANUALLY_CREATED = "MANUALLY_CREATED"
    UNSUBSCRIBED = "UNSUBSCRIBED"

# Constants for email types
class EmailType:
    WELCOME = "welcome"
    CREDENTIALS = "credentials"
    ROTATION_NOTICE = "rotation_notice"
    MANUAL_CONFIRMATION = "manual_confirmation"

# Retry decorator for AWS operations
def retry_with_backoff(max_retries=3, backoff_factor=2):
    """
    Decorator for retrying AWS operations with exponential backoff
    
    Args:
        max_retries: Maximum number of retries before failing
        backoff_factor: Factor to multiply delay by after each failure
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (ClientError, EndpointConnectionError) as e:
                    last_exception = e
                    sleep_time = backoff_factor ** attempt
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {sleep_time} seconds...")
                        time.sleep(sleep_time)
                    else:
                        logger.error(f"All {max_retries} attempts failed.")
                        raise last_exception
        return wrapper
    return decorator

def get_environment_variables():
    """
    Load and validate required environment variables
    
    Returns:
        Dict of environment variables
    
    Raises:
        EnvironmentError: If required variable is missing
    """
    required_vars = [
        'AWS_ACCOUNT_ID',
        'DYNAMODB_TABLE',
        'LLM_GROUP_NAME',
        'ROTATION_HANDLER_ARN',
        'SNS_TOPIC_ARN',
        'REGION'
    ]

    env_vars = {}
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            logger.error(f'Environment variable {var} is missing')
            raise EnvironmentError(f'Missing environment variable: {var}')
        env_vars[var] = value

    return env_vars

def validate_email(email: str) -> bool:
    """
    Validate email format
    
    Args:
        email: Email to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not email:
        return False
        
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(email_pattern.match(email))

def validate_username(username: str) -> bool:
    """
    Validate username format for IAM compatibility
    
    Args:
        username: Username to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not username:
        return False
    
    # IAM usernames must be alphanumeric, including these characters: plus (+), equal (=), comma (,), period (.), at (@), underscore (_), and hyphen (-)
    # Length must be between 1-64 characters
    pattern = re.compile(r'^[a-zA-Z0-9+=,.@_-]{1,64}$')
    return bool(pattern.match(username))

def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent injection
    
    Args:
        input_str: String to sanitize
        
    Returns:
        Sanitized string
    """
    if not isinstance(input_str, str):
        return str(input_str)
    
    # Remove any control characters and ensure proper encoding
    return re.sub(r'[^\x20-\x7E]', '', input_str)

def extract_base_secret_name(secret_arn: str, user_name: str) -> str:
    """
    Extract the base secret name from ARN or secret name
    
    Args:
        secret_arn: The ARN or name of the secret
        user_name: Username as fallback
        
    Returns:
        The base name of the secret without random suffixes
    """
    try:
        # Extract name part from ARN if needed
        if ':' in secret_arn:
            full_name = secret_arn.split(':')[-1]
        else:
            full_name = secret_arn
        
        # Check for possible random suffix (-Xyz123)
        parts = full_name.split('-')
        
        # If the last part is exactly 6 alphanumeric characters, it's likely a random suffix
        if len(parts) > 3 and len(parts[-1]) == 6 and parts[-1].isalnum():
            clean_name = '-'.join(parts[:-1])
        else:
            clean_name = full_name
            
        return clean_name
    except Exception as e:
        logger.warning(f"Error extracting base secret name: {str(e)}")
        # Default fallback
        return f"user-{user_name}-access-key"

def generate_timestamp() -> str:
    """
    Generate current timestamp in ISO format
    
    Returns:
        Timestamp string
    """
    return datetime.utcnow().isoformat()

def format_error_response(error_message: str, status_code: int = 400) -> Dict:
    """
    Format error response for API Gateway
    
    Args:
        error_message: Error message
        status_code: HTTP status code
        
    Returns:
        Formatted error response
    """
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': error_message})
    }

def format_success_response(message: str, data: Dict = None) -> Dict:
    """
    Format success response for API Gateway
    
    Args:
        message: Success message
        data: Optional data to include
        
    Returns:
        Formatted success response
    """
    response_body = {'message': message}
    if data:
        response_body.update(data)
        
    return {
        'statusCode': 200,
        'body': json.dumps(response_body)
    }

def is_valid_arn(arn: str) -> bool:
    """
    Validate ARN format
    
    Args:
        arn: ARN to validate
        
    Returns:
        True if valid ARN format, False otherwise
    """
    if not arn or not isinstance(arn, str):
        return False
        
    # Valid ARN format: arn:partition:service:region:account-id:resource-id
    return arn.startswith('arn:') and arn.count(':') >= 5

# Initialize AWS clients - can be overridden in tests
def get_aws_clients():
    """
    Initialize AWS clients
    
    Returns:
        Dict of AWS clients
    """
    return {
        'dynamodb': boto3.resource('dynamodb'),
        'secrets_manager': boto3.client('secretsmanager'),
        'sns': boto3.client('sns'),
        'iam': boto3.client('iam'),
        'lambda_client': boto3.client('lambda')
    }

# Load environment variables once at module import
try:
    ENV = get_environment_variables()
except Exception as e:
    logger.error(f"Failed to load environment variables: {str(e)}")
    # Don't re-raise - let the Lambda handler deal with this
    ENV = {}

def log_event_safely(event: Dict) -> None:
    """
    Log event details while redacting sensitive information
    
    Args:
        event: Event data to log
    """
    # Deep copy and redact sensitive fields
    def redact_sensitive(obj):
        if isinstance(obj, dict):
            return {
                k: "***REDACTED***" if k.lower() in ["secret", "password", "key", "token", "credential"] 
                else redact_sensitive(v) for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [redact_sensitive(item) for item in obj]
        else:
            return obj
            
    try:
        safe_event = redact_sensitive(event)
        logger.info(f"Processing event: {json.dumps(safe_event)}")
    except Exception as e:
        logger.warning(f"Could not log event safely: {str(e)}")
