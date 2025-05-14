import json
import os
from typing import Dict, Any
from boto3.dynamodb.conditions import Attr

from .common import (
    logger, ENV, format_error_response, format_success_response, 
    validate_email, log_event_safely
)
from .state_manager import StateManager
from .subscription_verifier import SubscriptionVerifier

def lambda_handler(event, context):
    """
    Lambda handler for subscription renewal
    
    Args:
        event: Lambda event containing user identifier
            - email: Email address to renew
            - user_name: Alternatively, username to renew
        context: Lambda context
        
    Returns:
        Result of renewal operation
    """
    # Ensure environment variables are set up correctly
    if 'SNS_TOPIC_ARN' not in ENV or not ENV['SNS_TOPIC_ARN']:
        logger.error("SNS_TOPIC_ARN environment variable is missing or empty")
        # Set a default value if it's missing
        os.environ['SNS_TOPIC_ARN'] = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:034362028980:GPS_LLM_Secrets_Notifications_Topic')
    try:
        log_event_safely(event)
        logger.info(f"Processing subscription renewal request")
        
        # Extract email or username from request
        email = event.get('email')
        user_name = event.get('user_name')
        
        if not email and not user_name:
            logger.error("Missing required parameter: email or user_name")
            return format_error_response("Either email or user_name is required")
        
        # Validate email if provided
        if email and not validate_email(email):
            logger.error(f"Invalid email format: {email}")
            return format_error_response("Invalid email format")
        
        # Find the user
        state_manager = StateManager()
        user = None
        found_user_name = None
        
        # If email is provided, search for the user by email
        if email:
            # Use the DynamoDB scan operation with filter
            response = state_manager.table.scan(
                FilterExpression=Attr('email_address').eq(email)
            )
            items = response.get('Items', [])
            
            # Handle pagination for large results (unlikely in this case)
            while 'LastEvaluatedKey' in response and not items:
                response = state_manager.table.scan(
                    FilterExpression=Attr('email_address').eq(email),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))
                
            if items:
                found_user_name = items[0]['user_name']
                user = items[0]
        
        # If user_name is provided directly, look up by username
        if user_name and not user:
            user = state_manager.get_user_state(user_name)
            found_user_name = user_name if user else None
                
        # If no user was found
        if not found_user_name or not user:
            logger.error(f"User not found for: {email or user_name}")
            return format_error_response("User not found")
        
        # Process the renewal using the existing manual confirmation method
        verifier = SubscriptionVerifier()
        result = verifier.manually_confirm_user(found_user_name)
        
        if 'error' in result:
            logger.error(f"Error renewing subscription: {result['error']}")
            return format_error_response(result['error'])
        
        email_address = user.get('email_address', 'unknown')
        
        logger.info(f"Subscription renewal successful for {found_user_name} / {email_address}")
        return format_success_response(
            f"Renewal successful. A new confirmation email has been sent to {email_address}",
            {
                "user_name": found_user_name,
                "email_address": email_address,
                "subscription_arn": result.get('subscription_arn', 'unknown'),
                "renewal_timestamp": result.get('timestamp', '')
            }
        )
        
    except Exception as e:
        logger.exception(f"Error processing subscription renewal: {str(e)}")
        return format_error_response(f"Internal server error: {str(e)}", 500)
