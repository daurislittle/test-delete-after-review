import json
import os
from typing import Dict, Any, Optional, List, Tuple
from botocore.exceptions import ClientError
from .common import (
    logger, ENV, retry_with_backoff, sanitize_input, 
    generate_timestamp, is_valid_arn, get_aws_clients, 
    validate_email, SubscriptionState
)

class SubscriptionManager:
    """
    Manages SNS subscriptions and their lifecycle
    """
    
    def __init__(self, sns_client=None, topic_arn=None):
        """
        Initialize SubscriptionManager with SNS resources
        
        Args:
            sns_client: Optional boto3 sns client for testing
            topic_arn: Optional SNS topic ARN override for testing
        """
        clients = get_aws_clients()
        self.sns = sns_client or clients['sns']
        
        # Get topic ARN with fallback options to ensure it's never None
        self.topic_arn = topic_arn or ENV.get('SNS_TOPIC_ARN') or os.environ.get('SNS_TOPIC_ARN')
        
        # If still None, use the default value
        if not self.topic_arn:
            self.topic_arn = 'arn:aws:sns:us-east-1:034362028980:GPS_LLM_Secrets_Notifications_Topic'
            logger.warning(f"SNS_TOPIC_ARN not found in environment, using default: {self.topic_arn}")
    
    @retry_with_backoff()
    def create_subscription(self, email_address: str) -> Tuple[str, str]:
        """
        Create a new SNS subscription for an email address
        
        Args:
            email_address: Email to subscribe
            
        Returns:
            Tuple of (subscription_arn, status)
        """
        # Validate email
        if not validate_email(email_address):
            logger.error(f"Invalid email format: {email_address}")
            return None, "INVALID_EMAIL"
        
        try:
            # First check if this email is already subscribed to our topic
            existing_sub = self.find_subscription_by_email(email_address)
            
            if existing_sub:
                sub_arn = existing_sub['SubscriptionArn']
                
                # If already confirmed, return it
                if sub_arn not in ['PendingConfirmation', 'pending confirmation']:
                    logger.info(f"Found existing confirmed subscription for {email_address}: {sub_arn}")
                    
                    # Ensure filter policy is set
                    self.update_subscription_filters(sub_arn, email_address)
                    return sub_arn, SubscriptionState.CONFIRMED
                else:
                    # Return the pending subscription ARN
                    logger.info(f"Found existing pending subscription for {email_address}")
                    return sub_arn, SubscriptionState.PENDING_CONFIRMATION
            
            # Create new subscription with filter policy
            response = self.sns.subscribe(
                TopicArn=self.topic_arn,
                Protocol='email',
                Endpoint=email_address,
                Attributes={
                    'FilterPolicy': json.dumps({'email': [email_address]}),
                    'FilterPolicyScope': 'MessageAttributes'
                    # Email protocol doesn't support RawMessageDelivery
                },
                ReturnSubscriptionArn=True
            )

            logger.info(f"Created new subscription with filter policy for {email_address}")
            
            # The ARN will be "PendingConfirmation" until user confirms
            return response['SubscriptionArn'], SubscriptionState.PENDING_CONFIRMATION
            
        except Exception as e:
            logger.error(f"Error creating subscription for {email_address}: {str(e)}")
            return None, "ERROR"
    
    @retry_with_backoff()
    def find_subscription_by_email(self, email_address: str) -> Optional[Dict[str, Any]]:
        """
        Find an existing SNS subscription for an email address
        
        Args:
            email_address: Email to look for
            
        Returns:
            Subscription info or None if not found
        """
        try:
            # List all subscriptions to the topic
            response = self.sns.list_subscriptions_by_topic(TopicArn=self.topic_arn)
            all_subscriptions = response['Subscriptions']
            
            # Handle pagination for large number of subscriptions
            while 'NextToken' in response:
                response = self.sns.list_subscriptions_by_topic(
                    TopicArn=self.topic_arn,
                    NextToken=response['NextToken']
                )
                all_subscriptions.extend(response['Subscriptions'])
            
            # Check if any of the subscriptions match this email
            for subscription in all_subscriptions:
                if subscription['Endpoint'] == email_address:
                    return subscription
            
            logger.info(f"No existing subscription found for {email_address}")
            return None
            
        except Exception as e:
            logger.error(f"Error finding subscription for {email_address}: {str(e)}")
            return None
    
    @retry_with_backoff()
    def check_subscription_status(self, subscription_arn: str) -> str:
        """
        Check the status of a subscription
        
        Args:
            subscription_arn: ARN or status string to check
            
        Returns:
            Subscription status
        """
        # Special cases for pending confirmation
        if subscription_arn in ["PendingConfirmation", "pending confirmation", "Pending Confirmation"]:
            return SubscriptionState.PENDING_CONFIRMATION
        
        # Validate ARN format before making API call
        if not is_valid_arn(subscription_arn):
            logger.warning(f"Invalid subscription ARN format: {subscription_arn}")
            return "INVALID_ARN"
        
        try:
            # Get subscription attributes
            attrs = self.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
            
            # Check status attribute
            status = attrs.get('Attributes', {}).get('PendingConfirmation', 'false')
            
            if status.lower() == 'true':
                return SubscriptionState.PENDING_CONFIRMATION
            else:
                return SubscriptionState.CONFIRMED
                
        except self.sns.exceptions.NotFoundException:
            logger.warning(f"Subscription not found: {subscription_arn}")
            return "NOT_FOUND"
        except ClientError as e:
            if "Invalid parameter: SubscriptionARN" in str(e):
                return "INVALID_ARN"
            logger.warning(f"Error getting subscription attributes for {subscription_arn}: {str(e)}")
            return "ERROR"
    
    @retry_with_backoff()
    def update_subscription_filters(self, subscription_arn: str, email_address: str) -> bool:
        """
        Update the filter policy for a subscription
        
        Args:
            subscription_arn: ARN of subscription to update
            email_address: Email address for filter policy
            
        Returns:
            True if successful, False otherwise
        """
        # Don't try to update policies for pending confirmations
        if subscription_arn in ["PendingConfirmation", "pending confirmation", "Pending Confirmation"]:
            logger.info(f"Skipping filter policy update for pending confirmation")
            return False
        
        # Validate ARN format
        if not is_valid_arn(subscription_arn):
            logger.warning(f"Invalid ARN format for filter policy update: {subscription_arn}")
            return False
        
        try:
            # Get current attributes to check if filter policy exists
            current_attributes = self.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
            current_filter = current_attributes.get('Attributes', {}).get('FilterPolicy')
            current_scope = current_attributes.get('Attributes', {}).get('FilterPolicyScope', 'MessageBody')
            
            # Construct filter policy - match exactly this email address
            filter_policy = json.dumps({
                'email': [email_address]
            })
            
            # Only update if filter doesn't exist or is incorrect
            if not current_filter or email_address not in current_filter:
                # Set filter policy
                self.sns.set_subscription_attributes(
                    SubscriptionArn=subscription_arn, 
                    AttributeName='FilterPolicy', 
                    AttributeValue=filter_policy
                )
                
                # Ensure filter applies to message attributes if not already set
                if current_scope != 'MessageAttributes':
                    self.sns.set_subscription_attributes(
                        SubscriptionArn=subscription_arn, 
                        AttributeName='FilterPolicyScope', 
                        AttributeValue='MessageAttributes'
                    )
                
                logger.info(f"Updated filter policy for subscription {subscription_arn}")
                return True
            else:
                logger.info(f"Filter policy already correctly set for {subscription_arn}")
                return True
                
        except Exception as e:
            logger.error(f"Error updating filter policy: {str(e)}")
            return False
    
    @retry_with_backoff()
    def refresh_subscription(self, email_address: str, old_subscription_arn: str = None) -> Tuple[str, str]:
        """
        Refresh a subscription by unsubscribing and creating a new one
        
        Args:
            email_address: Email to refresh subscription for
            old_subscription_arn: Optional ARN of previous subscription
            
        Returns:
            Tuple of (subscription_arn, status)
        """
        # First try to unsubscribe if we have a valid ARN
        if old_subscription_arn and is_valid_arn(old_subscription_arn):
            try:
                self.sns.unsubscribe(SubscriptionArn=old_subscription_arn)
                logger.info(f"Unsubscribed old subscription {old_subscription_arn}")
            except Exception as e:
                logger.warning(f"Error unsubscribing old subscription: {str(e)}")
                # Continue even if unsubscribe fails
        
        # Create new subscription
        return self.create_subscription(email_address)
    
    @retry_with_backoff()
    def check_all_user_subscriptions(self, email_address: str) -> List[Dict[str, Any]]:
        """
        Check if a user has any subscriptions across all SNS topics
        
        Args:
            email_address: Email address to check
            
        Returns:
            List of all subscriptions for this email
        """
        try:
            # List all subscriptions (not just for our topic)
            response = self.sns.list_subscriptions()
            all_subscriptions = response['Subscriptions']
            
            # Handle pagination
            while 'NextToken' in response:
                response = self.sns.list_subscriptions(NextToken=response['NextToken'])
                all_subscriptions.extend(response['Subscriptions'])
            
            # Filter for the specific email
            user_subscriptions = [sub for sub in all_subscriptions if sub.get('Endpoint') == email_address]
            
            logger.info(f"Found {len(user_subscriptions)} total subscriptions for {email_address}")
            return user_subscriptions
            
        except Exception as e:
            logger.error(f"Error listing all subscriptions: {str(e)}")
            return []
    
    @retry_with_backoff()
    def set_subscription_for_manual_confirmation(self, email_address: str) -> Tuple[str, str]:
        """
        Create a subscription specifically for manual confirmation
        Used when automatic confirmation links expire
        
        Args:
            email_address: Email to subscribe
            
        Returns:
            Tuple of (subscription_arn, status)
        """
        try:
            # First check if this email is already subscribed
            existing_sub = self.find_subscription_by_email(email_address)
            
            if existing_sub:
                sub_arn = existing_sub['SubscriptionArn']
                
                # If already confirmed, return it
                if sub_arn not in ['PendingConfirmation', 'pending confirmation']:
                    logger.info(f"Found existing confirmed subscription for manual process: {sub_arn}")
                    
                    # Ensure filter policy is set
                    self.update_subscription_filters(sub_arn, email_address)
                    return sub_arn, SubscriptionState.CONFIRMED
                else:
                    # For pending subscriptions, unsubscribe and create new one
                    try:
                        # Can't unsubscribe pending confirmations directly via API
                        # Instead just create a new one
                        logger.info(f"Found pending subscription, creating new one")
                    except Exception as e:
                        logger.warning(f"Error handling existing pending subscription: {str(e)}")
            
            # Create new subscription with special attributes
            response = self.sns.subscribe(
                TopicArn=self.topic_arn,
                Protocol='email',
                Endpoint=email_address,
                Attributes={
                    'FilterPolicy': json.dumps({'email': [email_address]}),
                    'FilterPolicyScope': 'MessageAttributes'
                    # Email protocol doesn't support RawMessageDelivery
                },
                ReturnSubscriptionArn=True
            )
            
            logger.info(f"Created subscription for manual confirmation: {email_address}")
            return response['SubscriptionArn'], SubscriptionState.MANUALLY_CREATED
            
        except Exception as e:
            logger.error(f"Error setting up manual confirmation for {email_address}: {str(e)}")
            return None, "ERROR"
    
    @retry_with_backoff()
    def send_notification(self, email_address: str, subject: str, message: str, 
                          message_type: str = "standard", message_id: str = None) -> Dict[str, Any]:
        """
        Send notification via SNS
        
        Args:
            email_address: Email to send to
            subject: Email subject
            message: Email body
            message_type: Type of message
            message_id: Optional unique ID for message
            
        Returns:
            SNS publish response
        """
        try:
            # Find the subscription first to ensure it's active
            subscription = self.find_subscription_by_email(email_address)
            
            if not subscription:
                logger.error(f"No subscription found for {email_address}")
                return None
                
            # Check if subscription is confirmed
            sub_arn = subscription['SubscriptionArn']
            if sub_arn in ['PendingConfirmation', 'pending confirmation']:
                logger.warning(f"Subscription for {email_address} is still pending confirmation")
                return None
            
            # Update the filter policy to ensure delivery
            self.update_subscription_filters(sub_arn, email_address)
            
            # Generate a unique ID if not provided
            unique_id = message_id or f"{message_type}-{email_address}-{generate_timestamp()}"
            
            # Message attributes for filtering
            message_attributes = {
                'email': {
                    'DataType': 'String',
                    'StringValue': email_address
                },
                'message_type': {
                    'DataType': 'String',
                    'StringValue': message_type
                },
                'notification_id': {
                    'DataType': 'String',
                    'StringValue': unique_id
                }
            }
            
            # Publish the message
            response = self.sns.publish(
                TopicArn=self.topic_arn,
                Message=message,
                Subject=subject,
                MessageAttributes=message_attributes
            )
            
            logger.info(f"Sent notification to {email_address} with MessageId: {response['MessageId']}")
            return response
            
        except Exception as e:
            logger.error(f"Error sending notification to {email_address}: {str(e)}")
            return None
