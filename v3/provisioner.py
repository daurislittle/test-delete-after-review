import json
import os
import boto3
import base64
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from .common import (
    logger, ENV, validate_email, validate_username, 
    sanitize_input, format_error_response, format_success_response,
    SubscriptionState, log_event_safely
)
from .user_manager import UserManager
from .subscription_manager import SubscriptionManager
from .state_manager import StateManager
from .notification_manager import NotificationManager

def parse_event_body(event):
    """
    Parse the API Gateway event body, handling different formats and encodings
    
    Args:
        event: API Gateway event
        
    Returns:
        Parsed body as dict
    """
    try:
        # Check if event is a string (for direct invocation)
        if isinstance(event, str):
            try:
                return json.loads(event)
            except json.JSONDecodeError:
                # If not valid JSON, try to parse as form data
                return urllib.parse.parse_qs(event)
                
        # Handle API Gateway format
        if 'body' in event:
            body = event['body']
            
            # Handle base64 encoded body
            if event.get('isBase64Encoded', False):
                try:
                    decode_bytes = base64.b64decode(body)
                    decode_string = decode_bytes.decode('utf-8')
                    return urllib.parse.parse_qs(decode_string)
                except Exception as e:
                    logger.error(f"Failed to decode base64 body: {str(e)}")
                    return {}
            
            # Try to parse as JSON
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                # If not valid JSON, try to parse as form data
                return urllib.parse.parse_qs(body)
        
        # Return the event itself if none of the above apply
        return event
    except Exception as e:
        logger.error(f"Error parsing event body: {str(e)}")
        return {}

def extract_users(body):
    """
    Extract user information from parsed event body
    
    Args:
        body: Parsed event body
        
    Returns:
        List of user objects with user_name and email_address
    """
    try:
        # Handle 'users' field which could be in various formats
        if 'users' in body:
            users_data = body['users']
            
            # Handle form-encoded list
            if isinstance(users_data, list) and len(users_data) == 1 and isinstance(users_data[0], str):
                try:
                    # Try to parse as JSON
                    parsed = json.loads(users_data[0])
                    users = parsed
                except json.JSONDecodeError:
                    users = users_data
            else:
                users = users_data
                
            # Ensure users is a list
            if isinstance(users, dict):
                users = [users]
                
            # Ensure each user has required fields
            return [
                {'user_name': u.get('user_name', ''), 'email_address': u.get('email_address', '')} 
                for u in users if isinstance(u, dict)
            ]
            
        # Handle 'text' field (from Slack)
        elif 'text' in body:
            text_data = body['text'][0] if isinstance(body['text'], list) else body['text']
            try:
                parsed_users = json.loads(text_data)
                if isinstance(parsed_users, dict):
                    parsed_users = [parsed_users]
                return parsed_users
            except json.JSONDecodeError:
                logger.error(f"Failed to parse users from text: {text_data}")
                return []
        
        # Handle direct user_name and email_address fields
        elif 'user_name' in body and 'email_address' in body:
            user_name = body['user_name'][0] if isinstance(body['user_name'], list) else body['user_name']
            email_address = body['email_address'][0] if isinstance(body['email_address'], list) else body['email_address']
            return [{'user_name': user_name, 'email_address': email_address}]
            
        # Return empty list if no recognized format
        logger.warning("No user information found in request")
        return []
        
    except Exception as e:
        logger.error(f"Error extracting users: {str(e)}")
        return []

def process_user(user_data: Dict[str, str]) -> Dict[str, Any]:
    """
    Process a single user: provision IAM, create subscription, and store state
    
    Args:
        user_data: User data with user_name and email_address
        
    Returns:
        Result dictionary with status and details
    """
    user_name = sanitize_input(user_data.get('user_name', ''))
    email_address = sanitize_input(user_data.get('email_address', ''))
    
    # Validate inputs
    if not user_name or not validate_username(user_name):
        return {'error': f"Invalid username: {user_name}"}
        
    if not email_address or not validate_email(email_address):
        return {'error': f"Invalid email: {email_address}"}
    
    try:
        # Initialize managers
        user_manager = UserManager()
        subscription_manager = SubscriptionManager()
        state_manager = StateManager()
        
        # Provision the user
        user_data, is_new_user = user_manager.provision_user(user_name, email_address)
        
        # Create subscription
        subscription_arn, status = subscription_manager.create_subscription(email_address)
        
        if not subscription_arn:
            return {'error': f"Failed to create subscription for {email_address}"}
            
        # Build state record
        state_data = {
            'user_name': user_name,
            'email_address': email_address,
            'secret_arn': user_data['secret_arn'],
            'subscription_arn': subscription_arn,
            'subscription_status': status,
            'email_sent': {
                'welcome': False,
                'credentials': False,
                'rotation_notice': False
            },
            'last_subscription_action': user_data.get('created_date'),
            'retry_count': 0
        }
        
        # Store state in DynamoDB
        state_manager.create_user_state(state_data)
        
        result_message = f"User {user_name} {'created' if is_new_user else 'updated'}"
        if status == SubscriptionState.CONFIRMED:
            result_message += ", subscription confirmed"
        else:
            result_message += ", subscription pending confirmation"
            
        return {
            'success': True, 
            'message': result_message,
            'user_name': user_name,
            'email_address': email_address,
            'subscription_status': status
        }
        
    except Exception as e:
        logger.exception(f"Error processing user {user_name}: {str(e)}")
        return {'error': f"Error processing user {user_name}: {str(e)}"}

def slack_response(url: str, message: str) -> None:
    """
    Send response back to Slack if URL is provided
    
    Args:
        url: Slack response URL
        message: Message to send
    """
    if not url or not url.startswith('https://hooks.slack.com/'):
        return
        
    try:
        import urllib3
        http = urllib3.PoolManager()
        
        # Limit message length for security
        safe_message = str(message)[:1000]
        
        payload = json.dumps({'text': safe_message}).encode('utf-8')
        
        http.request(
            'POST',
            url,
            body=payload,
            headers={'Content-Type': 'application/json'},
            timeout=5.0
        )
    except Exception as e:
        logger.error(f"Error sending Slack response: {str(e)}")

def lambda_handler(event, context):
    """
    Main Lambda handler for user provisioning
    
    Args:
        event: Lambda event (API Gateway or direct invocation)
        context: Lambda context
        
    Returns:
        API Gateway response or direct result
    """
    try:
        log_event_safely(event)
        
        # Parse the event body
        body = parse_event_body(event)
        
        # Get response URL for async responses (e.g., Slack)
        response_url = None
        if 'response_url' in body:
            response_url = body['response_url'][0] if isinstance(body['response_url'], list) else body['response_url']
            
        # Extract users to provision
        users = extract_users(body)
        
        if not users:
            error_msg = "No valid user information provided"
            logger.error(error_msg)
            return format_error_response(error_msg)
            
        # Initial response for async requests
        if response_url:
            slack_response(response_url, f"Processing provisioning request for {len(users)} user(s)...")
            
        # Process each user
        results = [process_user(user) for user in users]
        
        # Format the response
        if len(results) == 1:
            result = results[0]
            if 'error' in result:
                response = format_error_response(result['error'])
            else:
                response = format_success_response(result['message'], result)
        else:
            # Collect successful and failed results
            successes = [r for r in results if 'success' in r]
            errors = [r for r in results if 'error' in r]
            
            if errors and not successes:
                response = format_error_response(f"All {len(errors)} user provisioning attempts failed")
            else:
                response = format_success_response(
                    f"Processed {len(results)} users: {len(successes)} successful, {len(errors)} failed",
                    {'results': results}
                )
                
        # Send async response if needed
        if response_url:
            slack_response(response_url, response['body'])
            
        return response
        
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        return format_error_response(f"Internal server error: {str(e)}", 500)
