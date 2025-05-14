import json
from typing import Dict, Any, Optional, Tuple
from botocore.exceptions import ClientError
from .common import (
    logger, ENV, retry_with_backoff, sanitize_input,
    generate_timestamp, validate_username, get_aws_clients
)

class UserManager:
    """
    Manages IAM user accounts, groups, and credentials
    """
    
    def __init__(self, iam_client=None, secrets_manager_client=None):
        """
        Initialize UserManager with AWS clients
        
        Args:
            iam_client: Optional boto3 IAM client for testing
            secrets_manager_client: Optional boto3 Secrets Manager client for testing
        """
        clients = get_aws_clients()
        self.iam = iam_client or clients['iam']
        self.secrets_manager = secrets_manager_client or clients['secrets_manager']
        self.group_name = ENV.get('LLM_GROUP_NAME')
        self.aws_account_id = ENV.get('AWS_ACCOUNT_ID')
        self.region = ENV.get('REGION')
    
    @retry_with_backoff()
    def ensure_user_exists(self, user_name: str) -> bool:
        """
        Ensure IAM user exists, create if not
        
        Args:
            user_name: Username to check/create
            
        Returns:
            True if user already existed, False if created
        """
        # Validate username format
        if not validate_username(user_name):
            logger.error(f"Invalid username format: {user_name}")
            raise ValueError(f"Invalid username format: {user_name}")
        
        try:
            # Check if user exists
            self.iam.get_user(UserName=user_name)
            logger.info(f"User {user_name} already exists")
            return True
        except self.iam.exceptions.NoSuchEntityException:
            # Create user if not exists
            try:
                self.iam.create_user(UserName=user_name)
                logger.info(f"User {user_name} created without console access")
                return False
            except Exception as e:
                logger.error(f"Failed to create user {user_name}: {str(e)}")
                raise
    
    @retry_with_backoff()
    def ensure_user_in_group(self, user_name: str, group_name: str = None) -> bool:
        """
        Ensure user belongs to the specified IAM group
        
        Args:
            user_name: Username to add to group
            group_name: Group name (default: LLM_GROUP_NAME from env)
            
        Returns:
            True if successful, False otherwise
        """
        group = group_name or self.group_name
        
        if not group:
            logger.error("No group name specified or found in environment")
            return False
        
        try:
            # List groups for user
            groups = self.iam.list_groups_for_user(UserName=user_name)['Groups']
            
            # Check if user already in group
            if any(g['GroupName'] == group for g in groups):
                logger.info(f"User {user_name} already in group {group}")
                return True
            
            # Add user to group
            self.iam.add_user_to_group(GroupName=group, UserName=user_name)
            logger.info(f"User {user_name} added to group {group}")
            return True
            
        except Exception as e:
            logger.error(f"Error managing group membership for {user_name}: {str(e)}")
            return False
    
    @retry_with_backoff()
    def create_access_key(self, user_name: str) -> Optional[Dict[str, Any]]:
        """
        Create new access key for user, managing existing keys
        
        Args:
            user_name: Username to create key for
            
        Returns:
            Access key information or None if error
        """
        try:
            # Check existing access keys
            existing_keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            
            # AWS limit is 2 access keys per user
            if len(existing_keys) >= 2:
                # Delete oldest key
                oldest_key = sorted(existing_keys, key=lambda k: k['CreateDate'])[0]
                logger.info(f"User {user_name} has reached key limit. Deleting oldest key {oldest_key['AccessKeyId']}")
                self.iam.delete_access_key(UserName=user_name, AccessKeyId=oldest_key['AccessKeyId'])
            
            # Create new key
            access_key = self.iam.create_access_key(UserName=user_name)['AccessKey']
            logger.info(f"Access key created for user {user_name}")
            
            return {
                'username': user_name,
                'access_key_id': access_key['AccessKeyId'],
                'secret_access_key': access_key['SecretAccessKey'],
                'created_date': generate_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Failed to create access key for user {user_name}: {str(e)}")
            return None
    
    @retry_with_backoff()
    def store_secret(self, user_name: str, email_address: str, access_key: Dict[str, Any]) -> Optional[str]:
        """
        Store access key in Secrets Manager
        
        Args:
            user_name: Username for secret
            email_address: Email address for tagging
            access_key: Access key details
            
        Returns:
            Secret ARN or None if error
        """
        secret_name = f'user-{user_name}-access-key'
        
        # Secret value with metadata
        secret_value = {
            'username': user_name,
            'access_key_id': access_key['access_key_id'],
            'secret_access_key': access_key['secret_access_key'],
            'last_updated': generate_timestamp()
        }
        
        try:
            # Check if secret already exists
            try:
                existing_secret = self.secrets_manager.describe_secret(SecretId=secret_name)
                
                # Update existing secret
                self.secrets_manager.put_secret_value(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_value)
                )
                
                # Update tags
                self.secrets_manager.tag_resource(
                    SecretId=secret_name,
                    Tags=[
                        {'Key': 'User', 'Value': user_name},
                        {'Key': 'Email', 'Value': email_address},
                        {'Key': 'LastUpdated', 'Value': generate_timestamp()},
                        {'Key': 'InitialProvision', 'Value': generate_timestamp()}
                    ]
                )
                
                secret_arn = existing_secret['ARN']
                logger.info(f"Updated existing secret for {user_name}")
                
            except self.secrets_manager.exceptions.ResourceNotFoundException:
                # Create new secret
                create_response = self.secrets_manager.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_value),
                    Tags=[
                        {'Key': 'User', 'Value': user_name},
                        {'Key': 'Email', 'Value': email_address},
                        {'Key': 'CreatedAt', 'Value': generate_timestamp()},
                        {'Key': 'InitialProvision', 'Value': generate_timestamp()}
                    ]
                )
                
                secret_arn = create_response['ARN']
                logger.info(f"Created new secret for {user_name}")
            
            # Configure rotation when available
            self.configure_secret_rotation(secret_name)
            
            return secret_arn
            
        except Exception as e:
            logger.error(f"Error storing secret for user {user_name}: {str(e)}")
            return None
    
    @retry_with_backoff()
    def configure_secret_rotation(self, secret_name: str) -> bool:
        """
        Configure automatic rotation for a secret
        
        Args:
            secret_name: Name of secret to configure
            
        Returns:
            True if successful, False otherwise
        """
        # Rotation lambda ARN from environment
        rotation_lambda_arn = ENV.get('ROTATION_HANDLER_ARN')
        
        if not rotation_lambda_arn:
            logger.warning("No rotation lambda ARN found in environment, skipping rotation setup")
            return False
        
        try:
            # Set rotation with 90-day schedule
            self.secrets_manager.rotate_secret(
                SecretId=secret_name,
                RotationLambdaARN=rotation_lambda_arn,
                RotationRules={
                    'AutomaticallyAfterDays': 90
                }
            )
            
            logger.info(f"Configured rotation for secret {secret_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error configuring rotation for secret {secret_name}: {str(e)}")
            return False
    
    def provision_user(self, user_name: str, email_address: str) -> Tuple[Dict[str, Any], bool]:
        """
        Complete user provisioning process
        
        Args:
            user_name: Username to provision
            email_address: Email address for user
            
        Returns:
            Tuple of (user_data, is_new_user)
        """
        try:
            # Check if user exists
            is_new_user = not self.ensure_user_exists(user_name)
            
            # Ensure group membership
            self.ensure_user_in_group(user_name)
            
            # Create access key
            access_key = self.create_access_key(user_name)
            
            if not access_key:
                logger.error(f"Failed to create access key for user {user_name}")
                raise Exception(f"Failed to create access key for user {user_name}")
            
            # Store in Secrets Manager
            secret_arn = self.store_secret(user_name, email_address, access_key)
            
            if not secret_arn:
                logger.error(f"Failed to store secret for user {user_name}")
                raise Exception(f"Failed to store secret for user {user_name}")
            
            # Return combined user data
            user_data = {
                'user_name': user_name,
                'email_address': email_address,
                'secret_arn': secret_arn,
                'is_new_user': is_new_user,
                'access_key_id': access_key['access_key_id']
            }
            
            logger.info(f"Successfully provisioned user {user_name}")
            return user_data, is_new_user
            
        except Exception as e:
            logger.error(f"Error provisioning user {user_name}: {str(e)}")
            raise
    
    @retry_with_backoff()
    def get_secret_url(self, secret_arn: str) -> str:
        """
        Generate console URL for accessing a secret
        
        Args:
            secret_arn: ARN of secret
            
        Returns:
            URL to access secret in console
        """
        try:
            if ':' in secret_arn:
                # Extract name from ARN
                secret_name = secret_arn.split(':')[-1]
            else:
                secret_name = secret_arn
                
            # Build console URL
            region = self.region or 'us-east-1'
            url = f"https://{region}.console.aws.amazon.com/secretsmanager/secret?name={secret_name}&region={region}"
            
            return url
            
        except Exception as e:
            logger.warning(f"Error generating secret URL: {str(e)}")
            # Fallback to generic URL
            return f"https://console.aws.amazon.com/secretsmanager/home"
    
    @retry_with_backoff()
    def verify_access_key(self, user_name: str, access_key_id: str) -> bool:
        """
        Verify that an access key exists and is active
        
        Args:
            user_name: Username to check
            access_key_id: Access key ID to verify
            
        Returns:
            True if key is active, False otherwise
        """
        try:
            keys = self.iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            
            # Check for matching active key
            for key in keys:
                if key['AccessKeyId'] == access_key_id and key['Status'] == 'Active':
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error verifying access key for user {user_name}: {str(e)}")
            return False
