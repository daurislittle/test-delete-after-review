import json
import boto3
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from .common import (
    logger, ENV, retry_with_backoff, log_event_safely,
    generate_timestamp, format_error_response, format_success_response
)
from .state_manager import StateManager
from .notification_manager import NotificationManager

class RotationHandler:
    """
    Manages credential rotation and notifications
    """
    
    def __init__(self):
        """Initialize components"""
        self.secrets_manager = boto3.client('secretsmanager')
        self.iam = boto3.client('iam')
        self.lambda_client = boto3.client('lambda')
        self.state_manager = StateManager()
        self.notification_manager = NotificationManager()
        
    @retry_with_backoff()
    def handle_rotation_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle Secret Manager rotation event
        
        Args:
            event: Rotation event from Secrets Manager
            
        Returns:
            Result of rotation step
        """
        # Check required parameters
        required_params = ['SecretId', 'ClientRequestToken', 'Step']
        missing_params = [param for param in required_params if param not in event]
        
        if missing_params:
            error_msg = f"Missing required rotation parameters: {', '.join(missing_params)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
            
        secret_id = event['SecretId']
        token = event['ClientRequestToken']
        step = event['Step']
        
        # Check if this is a newly provisioned secret - prevent rotation if needed
        try:
            metadata = self.secrets_manager.describe_secret(SecretId=secret_id)
            
            # Check for InitialProvision tag
            tags = {tag['Key']: tag['Value'] for tag in metadata.get('Tags', [])}
            
            if 'InitialProvision' in tags:
                # Parse the provision timestamp
                provision_time_str = tags['InitialProvision']
                
                try:
                    provision_time = datetime.fromisoformat(provision_time_str)
                    current_time = datetime.now(provision_time.tzinfo if hasattr(provision_time, 'tzinfo') else None)
                    days_since_provision = (current_time - provision_time).total_seconds() / (24 * 3600)
                    
                    # If provisioned less than 90 days ago, skip rotation
                    if days_since_provision < 90:
                        logger.info(f"Secret {secret_id} was provisioned {days_since_provision:.1f} days ago. "
                                   f"Skipping rotation until 90 days have passed.")
                        
                        # Remove tag if almost 90 days to allow future rotations
                        if days_since_provision > 89:
                            new_tags = [tag for tag in metadata.get('Tags', []) if tag['Key'] != 'InitialProvision']
                            self.secrets_manager.tag_resource(
                                SecretId=secret_id,
                                Tags=new_tags
                            )
                            logger.info(f"Removed InitialProvision tag as secret is now {days_since_provision:.1f} days old")
                            
                        return {
                            'status': 'deferred',
                            'message': f"Rotation skipped for newly provisioned secret ({days_since_provision:.1f} days old)",
                            'days_since_provision': days_since_provision
                        }
                except ValueError as e:
                    logger.warning(f"Error parsing InitialProvision timestamp: {str(e)}")
        except Exception as e:
            logger.warning(f"Error checking secret metadata: {str(e)}")
        
        # Proceed with normal rotation flow
        logger.info(f"Processing {step} rotation step for secret {secret_id}")
        
        try:
            if step == "createSecret":
                return self.create_secret(secret_id, token)
            elif step == "setSecret":
                return self.set_secret(secret_id, token)
            elif step == "testSecret":
                return self.test_secret(secret_id, token)
            elif step == "finishSecret":
                return self.finish_secret(secret_id, token)
            else:
                raise ValueError(f"Invalid rotation step: {step}")
        except Exception as e:
            logger.exception(f"Error during {step} rotation step for {secret_id}: {str(e)}")
            raise
    
    @retry_with_backoff()
    def create_secret(self, secret_id: str, token: str) -> Dict[str, Any]:
        """
        Create new secret for rotation (createSecret step)
        
        Args:
            secret_id: Secret ARN or name
            token: Client request token
            
        Returns:
            Rotation result
        """
        try:
            # Get current version metadata
            metadata = self.secrets_manager.describe_secret(SecretId=secret_id)
            tags = {tag['Key']: tag['Value'] for tag in metadata.get('Tags', [])}
            
            # Extract user info from tags
            user_name = tags.get('User')
            
            if not user_name:
                # Try to get username from secret value
                secret_value = json.loads(
                    self.secrets_manager.get_secret_value(SecretId=secret_id)['SecretString']
                )
                user_name = secret_value.get('username')
            
            if not user_name:
                raise ValueError(f"Cannot identify username for secret {secret_id}")
            
            # Check existing access keys
            existing_keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            if len(existing_keys) >= 2:
                # Delete the oldest key
                oldest_key = min(existing_keys, key=lambda k: k['CreateDate'])
                self.iam.delete_access_key(UserName=user_name, AccessKeyId=oldest_key['AccessKeyId'])
                logger.info(f"Deleted oldest access key {oldest_key['AccessKeyId']} for {user_name}")
            
            # Create new access key
            new_access_key = self.iam.create_access_key(UserName=user_name)['AccessKey']
            
            # Create new secret version
            new_secret = {
                'username': user_name,
                'access_key_id': new_access_key['AccessKeyId'],
                'secret_access_key': new_access_key['SecretAccessKey'],
                'status': 'PENDING',
                'last_updated': generate_timestamp()
            }
            
            # Store new version with AWSPENDING stage
            self.secrets_manager.put_secret_value(
                SecretId=secret_id,
                ClientRequestToken=token,
                SecretString=json.dumps(new_secret),
                VersionStages=['AWSPENDING']
            )
            
            logger.info(f"Created new secret version for {user_name}")
            return {
                'status': 'success',
                'step': 'createSecret',
                'user': user_name,
                'keyId': new_access_key['AccessKeyId']
            }
            
        except self.secrets_manager.exceptions.ResourceExistsException:
            # Version already exists, just return success
            logger.info(f"AWSPENDING version already exists for {secret_id}")
            return {
                'status': 'success',
                'step': 'createSecret',
                'message': 'AWSPENDING version already exists'
            }
    
    @retry_with_backoff()
    def set_secret(self, secret_id: str, token: str) -> Dict[str, Any]:
        """
        Set secret reference (setSecret step)
        For IAM users, this step is a no-op
        
        Args:
            secret_id: Secret ARN or name
            token: Client request token
            
        Returns:
            Rotation result
        """
        # No action needed for this step with IAM users
        return {
            'status': 'success',
            'step': 'setSecret',
            'message': 'No action required for this step'
        }
    
    @retry_with_backoff()
    def test_secret(self, secret_id: str, token: str) -> Dict[str, Any]:
        """
        Test the new secret (testSecret step)
        
        Args:
            secret_id: Secret ARN or name
            token: Client request token
            
        Returns:
            Rotation result
        """
        try:
            # Get the pending secret
            pending_secret = json.loads(
                self.secrets_manager.get_secret_value(
                    SecretId=secret_id,
                    VersionStage='AWSPENDING'
                )['SecretString']
            )
            
            # Test the new credentials
            user_name = pending_secret['username']
            access_key_id = pending_secret['access_key_id']
            secret_access_key = pending_secret['secret_access_key']
            
            # Create a test session with new credentials
            test_session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key
            )
            
            # Test IAM client with new credentials
            test_iam = test_session.client('iam')
            
            # Try to get user info with new credentials
            max_retries = 5
            success = False
            
            for attempt in range(max_retries):
                try:
                    test_iam.get_user(UserName=user_name)
                    success = True
                    break
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.error(f"Failed to validate new credentials after {max_retries} attempts: {str(e)}")
                        raise
                    
                    # Exponential backoff between retries
                    time.sleep(2 ** attempt)
            
            if success:
                logger.info(f"Successfully validated new credentials for user {user_name}")
                return {
                    'status': 'success',
                    'step': 'testSecret',
                    'user': user_name,
                    'keyId': access_key_id
                }
            else:
                raise Exception(f"Failed to validate new credentials for {user_name}")
                
        except Exception as e:
            logger.error(f"Error testing new secret for {secret_id}: {str(e)}")
            raise
    
    @retry_with_backoff()
    def finish_secret(self, secret_id: str, token: str) -> Dict[str, Any]:
        """
        Finish secret rotation (finishSecret step)
        
        Args:
            secret_id: Secret ARN or name
            token: Client request token
            
        Returns:
            Rotation result
        """
        try:
            # Get current secret
            current_secret = json.loads(
                self.secrets_manager.get_secret_value(
                    SecretId=secret_id,
                    VersionStage='AWSCURRENT'
                )['SecretString']
            )
            
            user_name = current_secret['username']
            old_key_id = current_secret['access_key_id']
            
            # Disable the old access key
            self.iam.update_access_key(
                UserName=user_name,
                AccessKeyId=old_key_id,
                Status='Inactive'
            )
            
            logger.info(f"Disabled old access key {old_key_id} for {user_name}")
            
            # Move AWSPENDING to AWSCURRENT
            self.secrets_manager.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage='AWSCURRENT',
                MoveToVersionId=token,
                RemoveFromVersionId=self.secrets_manager.get_secret_value(
                    SecretId=secret_id,
                    VersionStage='AWSCURRENT'
                )['VersionId']
            )
            
            # Get metadata for email notification
            metadata = self.secrets_manager.describe_secret(SecretId=secret_id)
            tags = {tag['Key']: tag['Value'] for tag in metadata.get('Tags', [])}
            email_address = tags.get('Email')
            
            # Send notification if email is available
            if email_address:
                # Get user state
                state_record = self.state_manager.get_user_state(user_name)
                
                # Send rotation completed notice
                if state_record:
                    self.notification_manager.send_rotation_complete_notice(
                        email_address,
                        user_name,
                        secret_id
                    )
            
            # Update rotation info
            self.secrets_manager.tag_resource(
                SecretId=secret_id,
                Tags=[{
                    'Key': 'LastRotated',
                    'Value': generate_timestamp()
                }]
            )
            
            # Update rotation rules to ensure next rotation in 90 days
            try:
                self.secrets_manager.rotate_secret(
                    SecretId=secret_id,
                    RotationRules={
                        'AutomaticallyAfterDays': 90
                    }
                )
            except Exception as e:
                logger.warning(f"Error updating rotation rules: {str(e)}")
            
            logger.info(f"Finished rotating secret for {user_name}")
            return {
                'status': 'success',
                'step': 'finishSecret',
                'user': user_name,
                'old_key_id': old_key_id,
                'rotated_at': generate_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Error finishing rotation for {secret_id}: {str(e)}")
            raise
    
    @retry_with_backoff()
    def check_upcoming_rotations(self) -> Dict[str, Any]:
        """
        Check for upcoming rotations and send notifications
        
        Returns:
            Result of checks
        """
        try:
            # List all secrets with rotation enabled
            secrets = []
            next_token = None
            
            while True:
                if next_token:
                    response = self.secrets_manager.list_secrets(
                        Filters=[{'Key': 'rotation-enabled', 'Values': ['true']}],
                        NextToken=next_token
                    )
                else:
                    response = self.secrets_manager.list_secrets(
                        Filters=[{'Key': 'rotation-enabled', 'Values': ['true']}]
                    )
                    
                secrets.extend(response.get('SecretList', []))
                next_token = response.get('NextToken')
                
                if not next_token:
                    break
            
            logger.info(f"Found {len(secrets)} secrets with rotation enabled")
            
            # Check for secrets that will rotate in ~7 days
            notifications_sent = 0
            
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
                        
                        if user_name and email:
                            # Send notification
                            self.notification_manager.send_rotation_notice(
                                email,
                                user_name,
                                secret['ARN'],
                                days_until_rotation
                            )
                            notifications_sent += 1
                            logger.info(f"Sent upcoming rotation notification to {user_name}")
                            
                except Exception as e:
                    logger.error(f"Error processing secret {secret.get('Name')}: {str(e)}")
                    continue
            
            logger.info(f"Sent {notifications_sent} upcoming rotation notifications")
            return {
                'status': 'success',
                'total_secrets': len(secrets),
                'notifications_sent': notifications_sent
            }
            
        except Exception as e:
            logger.error(f"Error checking upcoming rotations: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error checking upcoming rotations: {str(e)}"
            }

def lambda_handler(event, context):
    """
    Lambda handler for rotation events and scheduled checks
    
    Args:
        event: Lambda event
        context: Lambda context
        
    Returns:
        Result of rotation or check
    """
    try:
        log_event_safely(event)
        handler = RotationHandler()
        
        # Check if this is a test notification request
        if event.get('test') == True and 'secret_name' in event:
            # This would trigger a test rotation notification
            result = {
                'status': 'not_implemented',
                'message': "Test rotation notification not implemented in this version"
            }
            return format_success_response("Test notification not implemented", result)
        
        # Check if this is a scheduled event to send advance notifications
        if event.get('source') == 'aws.events' and event.get('detail-type') == 'Scheduled Event':
            result = handler.check_upcoming_rotations()
            return format_success_response(
                f"Checked upcoming rotations. Sent {result['notifications_sent']} notifications.",
                result
            )
        
        # Check if this is a normal rotation event
        if all(k in event for k in ['SecretId', 'ClientRequestToken', 'Step']):
            result = handler.handle_rotation_event(event)
            return result
        
        # Unknown event type
        logger.warning(f"Unrecognized event format")
        return format_error_response("Unrecognized event format", 400)
        
    except Exception as e:
        logger.exception(f"Error in rotation handler: {str(e)}")
        return format_error_response(f"Internal server error: {str(e)}", 500)
