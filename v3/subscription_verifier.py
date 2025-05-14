import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from .common import (
    logger, ENV, retry_with_backoff, SubscriptionState, EmailType,
    format_error_response, format_success_response, log_event_safely
)
from .state_manager import StateManager
from .subscription_manager import SubscriptionManager
from .notification_manager import NotificationManager

class SubscriptionVerifier:
    """
    Verifies subscription status and sends appropriate emails
    """
    
    def __init__(self):
        """Initialize components"""
        self.state_manager = StateManager()
        self.subscription_manager = SubscriptionManager()
        self.notification_manager = NotificationManager()
        
    def verify_subscriptions(self):
        """
        Verify all user subscriptions and process accordingly
        
        Returns:
            Stats about verification process
        """
        # Find users with pending subscriptions
        pending_users = self.state_manager.get_users_by_state(SubscriptionState.PENDING_CONFIRMATION)
        
        # Find users with confirmed subscriptions but no welcome email
        confirm_no_email = self.state_manager.get_pending_welcome_emails()
        
        # Find users with expired confirmations
        expired_users = self.state_manager.get_expired_confirmations()
        
        processed_pending = self._process_pending_users(pending_users)
        processed_confirmed = self._process_confirmed_users(confirm_no_email)
        processed_expired = self._process_expired_users(expired_users)
        
        return {
            'pending_processed': processed_pending,
            'confirmed_processed': processed_confirmed,
            'expired_processed': processed_expired,
            'total_processed': processed_pending + processed_confirmed + processed_expired
        }
        
    def _process_pending_users(self, users: List[Dict[str, Any]]) -> int:
        """
        Process users with pending subscriptions
        
        Args:
            users: List of user records
            
        Returns:
            Number of processed users
        """
        processed = 0
        
        for user in users:
            user_name = user.get('user_name')
            email_address = user.get('email_address')
            subscription_arn = user.get('subscription_arn')
            
            if not user_name or not email_address or not subscription_arn:
                continue
                
            logger.info(f"Checking pending subscription for {user_name}")
            
            # Check subscription status
            current_status = self.subscription_manager.check_subscription_status(subscription_arn)
            
            if current_status == SubscriptionState.CONFIRMED:
                # Subscription was confirmed, update status
                logger.info(f"Subscription confirmed for {user_name}")
                self.state_manager.update_subscription_status(user_name, SubscriptionState.CONFIRMED)
                
                # Send credentials email now that subscription is confirmed
                self._send_credentials_email(user)
                
                processed += 1
                
            elif current_status == SubscriptionState.PENDING_CONFIRMATION:
                # Still pending, no action needed
                pass
            else:
                # Invalid ARN or other issue
                logger.warning(f"Invalid subscription status for {user_name}: {current_status}")
                
        return processed
    
    def _process_confirmed_users(self, users: List[Dict[str, Any]]) -> int:
        """
        Process users with confirmed subscriptions but missing welcome emails
        
        Args:
            users: List of user records
            
        Returns:
            Number of processed users
        """
        processed = 0
        
        for user in users:
            user_name = user.get('user_name')
            
            if not user_name:
                continue
                
            logger.info(f"Processing confirmed user without welcome email: {user_name}")
            
            # Send credentials email
            self._send_credentials_email(user)
            processed += 1
            
        return processed
    
    def _process_expired_users(self, users: List[Dict[str, Any]]) -> int:
        """
        Process users with expired confirmation links
        
        Args:
            users: List of user records
            
        Returns:
            Number of processed users
        """
        if not users:
            return 0
            
        processed = 0
        
        # Update all users to expired state
        for user in users:
            user_name = user.get('user_name')
            
            if not user_name:
                continue
                
            logger.info(f"Marking subscription as expired for {user_name}")
            
            # Update status to expired
            self.state_manager.update_subscription_status(
                user_name, 
                SubscriptionState.CONFIRMATION_EXPIRED
            )
            processed += 1
            
        # Send admin notification about expired confirmations
        try:
            self.notification_manager.send_expired_confirmation_admin_notice(users)
        except Exception as e:
            logger.error(f"Failed to send admin notification about expired confirmations: {str(e)}")
            
        return processed
    
    def _send_credentials_email(self, user: Dict[str, Any]) -> bool:
        """
        Send credentials email to confirmed user
        
        Args:
            user: User record
            
        Returns:
            True if successful, False otherwise
        """
        try:
            user_name = user.get('user_name')
            email_address = user.get('email_address')
            secret_arn = user.get('secret_arn')
            
            if not all([user_name, email_address, secret_arn]):
                logger.error(f"Missing required user data for sending credentials email")
                return False
            
            # Send credentials email if not sent
            if not user.get('email_sent', {}).get('credentials', False):
                if self.notification_manager.send_credentials_email(email_address, user_name, secret_arn):
                    self.state_manager.mark_email_sent(user_name, EmailType.CREDENTIALS)
                    
            return True
        except Exception as e:
            logger.error(f"Error sending welcome emails to {user.get('user_name')}: {str(e)}")
            return False
    
    def manually_confirm_user(self, user_name: str) -> Dict[str, Any]:
        """
        Manually confirm a user's subscription
        Used for admin API to fix expired confirmations
        
        Args:
            user_name: Username to process
            
        Returns:
            Result of manual confirmation
        """
        try:
            # Get user state
            user = self.state_manager.get_user_state(user_name)
            
            if not user:
                return {'error': f"User {user_name} not found"}
                
            email_address = user.get('email_address')
            
            if not email_address:
                return {'error': f"No email address found for {user_name}"}
                
            # Create manual subscription
            subscription_arn, status = self.subscription_manager.set_subscription_for_manual_confirmation(email_address)
            
            if not subscription_arn:
                return {'error': f"Failed to create subscription for {email_address}"}
                
            # Update user state
            self.state_manager.update_subscription_status(
                user_name, 
                SubscriptionState.MANUALLY_CREATED,
                subscription_arn
            )
            
            # Reset email flags to ensure emails are sent
            self.state_manager.update_user_state(user_name, {
                'email_sent': {
                    'welcome': False,
                    'credentials': False,
                    'rotation_notice': False
                }
            })
            
            # Send notification about manual confirmation
            self.notification_manager.send_manual_confirmation_email(email_address, user_name)
            
            return {
                'success': True,
                'message': f"Created manual subscription for {user_name}",
                'subscription_arn': subscription_arn,
                'status': status
            }
            
        except Exception as e:
            logger.error(f"Error manually confirming user {user_name}: {str(e)}")
            return {'error': f"Error manually confirming user: {str(e)}"}

def lambda_handler(event, context):
    """
    Lambda handler for subscription verification
    
    Args:
        event: Lambda event
        context: Lambda context
        
    Returns:
        Result of verification
    """
    try:
        log_event_safely(event)
        
        # Check if this is a manual confirmation request
        if event.get('manual_confirm'):
            user_name = event.get('user_name')
            
            if not user_name:
                return format_error_response("Missing user_name for manual confirmation")
                
            verifier = SubscriptionVerifier()
            result = verifier.manually_confirm_user(user_name)
            
            if 'error' in result:
                return format_error_response(result['error'])
            else:
                return format_success_response(result['message'], result)
        
        # Normal scheduled execution - verify all subscriptions
        verifier = SubscriptionVerifier()
        stats = verifier.verify_subscriptions()
        
        return format_success_response(
            f"Subscription verification completed. Processed {stats['total_processed']} users.",
            {
                'stats': stats,
                'timestamp': datetime.utcnow().isoformat()
            }
        )
        
    except Exception as e:
        logger.exception(f"Error in subscription verification: {str(e)}")
        return format_error_response(f"Internal server error: {str(e)}", 500)
