import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from .common import (
    logger, ENV, retry_with_backoff, EmailType, 
    format_error_response, format_success_response, log_event_safely
)
from .state_manager import StateManager
from .notification_manager import NotificationManager

class RotationNotifier:
    """
    Handles notifications about credential rotations
    """
    
    def __init__(self):
        """Initialize components"""
        self.state_manager = StateManager()
        self.notification_manager = NotificationManager()
        self.secrets_manager = boto3.client('secretsmanager')
    
    def handle_rotation_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process rotation event notification
        
        Args:
            event: Event data with rotation details
            
        Returns:
            Result of notification process
        """
        event_type = event.get('event')
        secret_arn = event.get('secret_arn')
        user_name = event.get('user_name')
        
        if not event_type:
            logger.error("Missing event type in rotation event")
            return {'error': "Missing event type"}
            
        if not secret_arn:
            logger.error("Missing secret ARN in rotation event")
            return {'error': "Missing secret ARN"}
            
        if not user_name:
            logger.error("Missing user name in rotation event")
            return {'error': "Missing user name"}
            
        # Handle different event types
        if event_type == 'rotated':
            return self._handle_rotation_completed(secret_arn, user_name)
        elif event_type == 'upcoming_rotation':
            days_remaining = event.get('days_remaining', 7)
            email = event.get('email')
            return self._handle_upcoming_rotation(secret_arn, user_name, email, days_remaining)
        else:
            logger.error(f"Unknown rotation event type: {event_type}")
            return {'error': f"Unknown event type: {event_type}"}
    
    def _handle_rotation_completed(self, secret_arn: str, user_name: str) -> Dict[str, Any]:
        """
        Handle completed rotation notification
        
        Args:
            secret_arn: ARN of secret that was rotated
            user_name: Username associated with secret
            
        Returns:
            Result of notification
        """
        try:
            # Get user state
            user = self.state_manager.get_user_state(user_name)
            
            if not user:
                logger.warning(f"User {user_name} not found in state database")
                
                # Try to get email from secret tags
                try:
                    metadata = self.secrets_manager.describe_secret(SecretId=secret_arn)
                    email_address = None
                    
                    for tag in metadata.get('Tags', []):
                        if tag['Key'] == 'Email':
                            email_address = tag['Value']
                            break
                            
                    if email_address:
                        # Create a temporary user record for notification
                        user = {
                            'user_name': user_name,
                            'email_address': email_address,
                            'secret_arn': secret_arn
                        }
                    else:
                        return {'error': f"No email found for user {user_name}"}
                except Exception as e:
                    logger.error(f"Error getting metadata for secret {secret_arn}: {str(e)}")
                    return {'error': f"No email found for user {user_name}"}
            
            # Send rotation completed notification
            email_address = user.get('email_address')
            if not email_address:
                return {'error': f"No email address found for user {user_name}"}
                
            result = self.notification_manager.send_rotation_complete_notice(
                email_address,
                user_name,
                secret_arn
            )
            
            if result:
                logger.info(f"Sent rotation completed notification to {user_name} ({email_address})")
                
                # Update user state if available
                if 'user_name' in user and self.state_manager.get_user_state(user_name):
                    self.state_manager.update_user_state(user_name, {
                        'last_rotation': datetime.utcnow().isoformat()
                    })
                
                return {
                    'success': True,
                    'message': f"Sent rotation completed notification to {user_name}",
                    'email_address': email_address
                }
            else:
                return {'error': f"Failed to send rotation notification to {email_address}"}
                
        except Exception as e:
            logger.error(f"Error handling rotation completed for {user_name}: {str(e)}")
            return {'error': f"Error sending rotation notification: {str(e)}"}
    
    def _handle_upcoming_rotation(self, secret_arn: str, user_name: str, 
                                email: Optional[str], days_remaining: int) -> Dict[str, Any]:
        """
        Handle upcoming rotation notification
        
        Args:
            secret_arn: ARN of secret that will be rotated
            user_name: Username associated with secret
            email: Optional email address
            days_remaining: Days until rotation
            
        Returns:
            Result of notification
        """
        try:
            # Get user state if email not directly provided
            if not email:
                user = self.state_manager.get_user_state(user_name)
                
                if not user:
                    logger.warning(f"User {user_name} not found in state database")
                    
                    # Try to get email from secret tags
                    try:
                        metadata = self.secrets_manager.describe_secret(SecretId=secret_arn)
                        
                        for tag in metadata.get('Tags', []):
                            if tag['Key'] == 'Email':
                                email = tag['Value']
                                break
                                
                        if not email:
                            return {'error': f"No email found for user {user_name}"}
                    except Exception as e:
                        logger.error(f"Error getting metadata for secret {secret_arn}: {str(e)}")
                        return {'error': f"No email found for user {user_name}"}
                else:
                    email = user.get('email_address')
            
            if not email:
                return {'error': f"No email address found for user {user_name}"}
                
            # Send upcoming rotation notification
            result = self.notification_manager.send_rotation_notice(
                email,
                user_name,
                secret_arn,
                days_remaining
            )
            
            if result:
                logger.info(f"Sent upcoming rotation notification to {user_name} ({email}) for rotation in {days_remaining} days")
                
                # Update user state if available
                user = self.state_manager.get_user_state(user_name)
                if user:
                    self.state_manager.update_user_state(user_name, {
                        'next_rotation': (datetime.utcnow() + timedelta(days=days_remaining)).isoformat(),
                        'rotation_notified': True
                    })
                
                return {
                    'success': True,
                    'message': f"Sent upcoming rotation notification to {user_name} for rotation in {days_remaining} days",
                    'email_address': email
                }
            else:
                return {'error': f"Failed to send rotation notification to {email}"}
                
        except Exception as e:
            logger.error(f"Error handling upcoming rotation for {user_name}: {str(e)}")
            return {'error': f"Error sending rotation notification: {str(e)}"}
    
    def process_bulk_notifications(self) -> Dict[str, Any]:
        """
        Process bulk rotation notifications (scheduled job)
        
        Returns:
            Result of notification process
        """
        try:
            # List all secrets with rotation enabled
            secrets_manager = boto3.client('secretsmanager')
            secrets = []
            next_token = None
            
            while True:
                if next_token:
                    response = secrets_manager.list_secrets(
                        Filters=[{'Key': 'rotation-enabled', 'Values': ['true']}],
                        NextToken=next_token
                    )
                else:
                    response = secrets_manager.list_secrets(
                        Filters=[{'Key': 'rotation-enabled', 'Values': ['true']}]
                    )
                    
                secrets.extend(response.get('SecretList', []))
                next_token = response.get('NextToken')
                
                if not next_token:
                    break
            
            logger.info(f"Found {len(secrets)} secrets with rotation enabled")
            
            # Check for secrets that will rotate in ~7 days
            notifications_sent = 0
            notification_failures = 0
            
            for secret in secrets:
                try:
                    # Skip secrets without NextRotationDate
                    if 'NextRotationDate' not in secret:
                        continue
                        
                    next_rotation = secret['NextRotationDate']
                    days_until_rotation = (next_rotation - datetime.now(next_rotation.tzinfo)).days
                    
                    # If rotation is in 6-8 days, send notification
                    if 6 <= days_until_rotation <= 8:
                        logger.info(f"Secret {secret['Name']} will rotate in {days_until_rotation} days")
                        
                        # Get user info from tags
                        user_name = None
                        email = None
                        
                        for tag in secret.get('Tags', []):
                            if tag['Key'] == 'User':
                                user_name = tag['Value']
                            elif tag['Key'] == 'Email':
                                email = tag['Value']
                        
                        # Only proceed if we have both username and email
                        if user_name and email:
                            result = self._handle_upcoming_rotation(
                                secret['ARN'], 
                                user_name, 
                                email, 
                                days_until_rotation
                            )
                            
                            if result.get('success'):
                                notifications_sent += 1
                            else:
                                notification_failures += 1
                                
                except Exception as e:
                    logger.error(f"Error processing secret {secret.get('Name')}: {str(e)}")
                    notification_failures += 1
                    continue
            
            logger.info(f"Processed bulk notifications: {notifications_sent} sent, {notification_failures} failed")
            return {
                'success': True,
                'notifications_sent': notifications_sent,
                'notification_failures': notification_failures
            }
                    
        except Exception as e:
            logger.error(f"Error processing bulk notifications: {str(e)}")
            return {'error': f"Error processing bulk notifications: {str(e)}"}

def lambda_handler(event, context):
    """
    Lambda handler for rotation notification events
    
    Args:
        event: Lambda event
        context: Lambda context
        
    Returns:
        Result of notification process
    """
    try:
        log_event_safely(event)
        notifier = RotationNotifier()
        
        # Check if this is a scheduled bulk notification job
        if event.get('source') == 'aws.events' and event.get('detail-type') == 'Scheduled Event':
            result = notifier.process_bulk_notifications()
            
            if 'error' in result:
                return format_error_response(result['error'])
            else:
                return format_success_response(
                    f"Successfully sent {result['notifications_sent']} rotation notifications",
                    result
                )
        
        # Check if this is a direct event from rotation lambda
        if 'event' in event and ('secret_arn' in event or 'user_name' in event):
            result = notifier.handle_rotation_event(event)
            
            if 'error' in result:
                return format_error_response(result['error'])
            else:
                return format_success_response(
                    result.get('message', "Rotation notification processed successfully"),
                    result
                )
        
        # Unknown event format
        logger.warning("Received unknown event format")
        return format_error_response("Unknown event format", 400)
        
    except Exception as e:
        logger.exception(f"Error in rotation notifier: {str(e)}")
        return format_error_response(f"Internal server error: {str(e)}", 500)
