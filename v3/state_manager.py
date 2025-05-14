import json
from typing import Dict, List, Any, Optional
from boto3.dynamodb.conditions import Attr, Key
from datetime import datetime, timedelta
from .common import (
    logger, ENV, retry_with_backoff, sanitize_input, 
    generate_timestamp, is_valid_arn, get_aws_clients
)

class StateManager:
    """
    Handles state management for user subscriptions in DynamoDB
    """
    
    def __init__(self, dynamodb_resource=None, table_name=None):
        """
        Initialize StateManager with DynamoDB resources
        
        Args:
            dynamodb_resource: Optional boto3 dynamodb resource for testing
            table_name: Optional table name override for testing
        """
        clients = get_aws_clients()
        self.dynamodb = dynamodb_resource or clients['dynamodb']
        self.table_name = table_name or ENV.get('DYNAMODB_TABLE', 'SecretSubscriptionsv2')
        self.table = self.dynamodb.Table(self.table_name)
    
    @retry_with_backoff()
    def get_user_state(self, user_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a user's current state from DynamoDB
        
        Args:
            user_name: Username to look up
            
        Returns:
            User state record or None if not found
        """
        try:
            # Sanitize input to prevent injection
            safe_user_name = sanitize_input(user_name)
            
            response = self.table.get_item(Key={'user_name': safe_user_name})
            if 'Item' in response:
                return response['Item']
            
            logger.info(f"User {safe_user_name} not found in state table")
            return None
        except Exception as e:
            logger.error(f"Error getting user state for {user_name}: {str(e)}")
            raise
    
    @retry_with_backoff()
    def update_user_state(self, user_name: str, updates: Dict[str, Any]) -> bool:
        """
        Update a user's state in DynamoDB
        
        Args:
            user_name: Username to update
            updates: Dictionary of attributes to update
            
        Returns:
            True if successful, False otherwise
        """
        # Sanitize inputs
        safe_user_name = sanitize_input(user_name)
        
        # Sanitize update values and prevent empty values
        sanitized_updates = {}
        for key, value in updates.items():
            if value is None or value == "":
                continue
            if isinstance(value, str):
                sanitized_updates[key] = sanitize_input(value)
            else:
                sanitized_updates[key] = value
        
        # Add last_updated timestamp
        sanitized_updates['last_updated'] = generate_timestamp()
        
        try:
            # Construct update expression and attribute values
            update_expression_parts = []
            expression_attr_values = {}
            
            for key, value in sanitized_updates.items():
                update_expression_parts.append(f"{key} = :{key}")
                expression_attr_values[f":{key}"] = value
            
            if not update_expression_parts:
                logger.warning(f"No valid updates for user {safe_user_name}")
                return False
                
            update_expression = "SET " + ", ".join(update_expression_parts)
            
            self.table.update_item(
                Key={'user_name': safe_user_name},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attr_values
            )
            
            logger.info(f"Updated state for user {safe_user_name}")
            return True
        except Exception as e:
            logger.error(f"Error updating user state for {user_name}: {str(e)}")
            return False
    
    @retry_with_backoff()
    def create_user_state(self, user_data: Dict[str, Any]) -> bool:
        """
        Create a new user state record in DynamoDB
        
        Args:
            user_data: User data dictionary containing required fields
            
        Returns:
            True if successful, False otherwise
        """
        required_fields = ['user_name', 'email_address']
        for field in required_fields:
            if field not in user_data or not user_data[field]:
                logger.error(f"Missing required field {field} for new user state")
                return False
        
        # Sanitize all string inputs
        sanitized_data = {}
        for key, value in user_data.items():
            if isinstance(value, str):
                sanitized_data[key] = sanitize_input(value)
            else:
                sanitized_data[key] = value
        
        # Add metadata fields
        timestamp = generate_timestamp()
        sanitized_data['created_at'] = timestamp
        sanitized_data['last_updated'] = timestamp
        
        # Initialize email_sent tracking if not provided
        if 'email_sent' not in sanitized_data:
            sanitized_data['email_sent'] = {
                'welcome': False,
                'credentials': False,
                'rotation_notice': False
            }
        
        # Initialize subscription_status if not provided
        if 'subscription_status' not in sanitized_data:
            sanitized_data['subscription_status'] = 'PENDING_CONFIRMATION'
        
        # Initialize retry_count if not provided
        if 'retry_count' not in sanitized_data:
            sanitized_data['retry_count'] = 0
            
        try:
            self.table.put_item(Item=sanitized_data)
            logger.info(f"Created state record for user {sanitized_data['user_name']}")
            return True
        except Exception as e:
            logger.error(f"Error creating user state: {str(e)}")
            return False
    
    @retry_with_backoff()
    def get_users_by_state(self, state_filter: str) -> List[Dict[str, Any]]:
        """
        Get users matching a specific subscription state
        
        Args:
            state_filter: Subscription state to filter by
            
        Returns:
            List of matching user records
        """
        try:
            response = self.table.scan(
                FilterExpression=Attr('subscription_status').eq(state_filter)
            )
            items = response.get('Items', [])
            
            # Handle pagination for large results
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(
                    FilterExpression=Attr('subscription_status').eq(state_filter),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))
            
            logger.info(f"Found {len(items)} users with state {state_filter}")
            return items
        except Exception as e:
            logger.error(f"Error querying users by state {state_filter}: {str(e)}")
            return []
    
    @retry_with_backoff()
    def get_expired_confirmations(self, hours_threshold: int = 72) -> List[Dict[str, Any]]:
        """
        Get users with pending confirmations older than the threshold
        
        Args:
            hours_threshold: Number of hours after which confirmation is considered expired (default 72 hours/3 days per AWS SNS)
            
        Returns:
            List of users with expired confirmations
        """
        try:
            # First get all pending confirmations
            pending_users = self.get_users_by_state('PENDING_CONFIRMATION')
            
            # Filter for those older than threshold
            cutoff_time = datetime.utcnow() - timedelta(hours=hours_threshold)
            cutoff_timestamp = cutoff_time.isoformat()
            
            expired_users = []
            for user in pending_users:
                # Check creation time
                created_at = user.get('created_at')
                last_subscription_action = user.get('last_subscription_action', created_at)
                
                # Use the most recent subscription action time
                check_time = last_subscription_action if last_subscription_action else created_at
                
                if check_time and check_time < cutoff_timestamp:
                    expired_users.append(user)
            
            logger.info(f"Found {len(expired_users)} users with expired confirmations")
            return expired_users
        except Exception as e:
            logger.error(f"Error getting expired confirmations: {str(e)}")
            return []
    
    @retry_with_backoff()
    def get_pending_welcome_emails(self) -> List[Dict[str, Any]]:
        """
        Get users who should receive welcome emails
        (confirmed subscription but email not sent)
        
        Returns:
            List of users pending welcome emails
        """
        try:
            response = self.table.scan(
                FilterExpression=Attr('subscription_status').eq('CONFIRMED') & 
                                Attr('email_sent.credentials').eq(False)
            )
            items = response.get('Items', [])
            
            # Handle pagination for large results
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(
                    FilterExpression=Attr('subscription_status').eq('CONFIRMED') & 
                                    Attr('email_sent.credentials').eq(False),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))
            
            logger.info(f"Found {len(items)} users pending welcome emails")
            return items
        except Exception as e:
            logger.error(f"Error getting users pending welcome emails: {str(e)}")
            return []
    
    @retry_with_backoff()
    def mark_email_sent(self, user_name: str, email_type: str) -> bool:
        """
        Mark a specific email type as sent for a user
        
        Args:
            user_name: Username to update
            email_type: Type of email that was sent
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Update the specific email type in the email_sent map
            self.table.update_item(
                Key={'user_name': sanitize_input(user_name)},
                UpdateExpression=f"SET email_sent.{email_type} = :true, last_updated = :timestamp",
                ExpressionAttributeValues={
                    ':true': True,
                    ':timestamp': generate_timestamp()
                }
            )
            
            logger.info(f"Marked {email_type} email as sent for user {user_name}")
            return True
        except Exception as e:
            logger.error(f"Error marking email as sent for {user_name}: {str(e)}")
            return False
    
    @retry_with_backoff()
    def update_subscription_status(self, user_name: str, status: str, subscription_arn: str = None) -> bool:
        """
        Update subscription status and ARN for a user
        
        Args:
            user_name: Username to update
            status: New subscription status
            subscription_arn: Optional new subscription ARN
            
        Returns:
            True if successful, False otherwise
        """
        updates = {
            'subscription_status': status,
            'last_subscription_action': generate_timestamp()
        }
        
        # Only update ARN if provided and valid
        if subscription_arn:
            if is_valid_arn(subscription_arn) or status == 'PENDING_CONFIRMATION':
                updates['subscription_arn'] = subscription_arn
            else:
                logger.warning(f"Invalid ARN provided for {user_name}: {subscription_arn}")
        
        return self.update_user_state(user_name, updates)
    
    @retry_with_backoff()
    def increment_retry_count(self, user_name: str) -> int:
        """
        Increment retry count for a user
        
        Args:
            user_name: Username to update
            
        Returns:
            New retry count or -1 if error
        """
        try:
            response = self.table.update_item(
                Key={'user_name': sanitize_input(user_name)},
                UpdateExpression="SET retry_count = if_not_exists(retry_count, :zero) + :one, last_updated = :timestamp",
                ExpressionAttributeValues={
                    ':one': 1,
                    ':zero': 0,
                    ':timestamp': generate_timestamp()
                },
                ReturnValues="UPDATED_NEW"
            )
            
            new_count = response.get('Attributes', {}).get('retry_count', 0)
            logger.info(f"Incremented retry count for {user_name} to {new_count}")
            return new_count
        except Exception as e:
            logger.error(f"Error incrementing retry count for {user_name}: {str(e)}")
            return -1
    
    @retry_with_backoff()
    def delete_user_state(self, user_name: str) -> bool:
        """
        Delete a user's state record
        
        Args:
            user_name: Username to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.table.delete_item(Key={'user_name': sanitize_input(user_name)})
            logger.info(f"Deleted state record for user {user_name}")
            return True
        except Exception as e:
            logger.error(f"Error deleting user state for {user_name}: {str(e)}")
            return False
    
    @retry_with_backoff()
    def reset_retry_count(self, user_name: str) -> bool:
        """
        Reset retry count for a user
        
        Args:
            user_name: Username to update
            
        Returns:
            True if successful, False otherwise
        """
        return self.update_user_state(user_name, {'retry_count': 0})
