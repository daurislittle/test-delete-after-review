# AWS Secret Subscription Management System

This redesigned system manages AWS user provisioning, subscription confirmations, and credential rotation with improved handling of expired confirmation links and proper state tracking.

## System Architecture

The new architecture is built with a modular, state-driven approach to properly handle various edge cases like expired confirmation links. It consists of several core components and Lambda functions working together.

### Core Components

1. **StateManager**: Tracks user state in DynamoDB with explicit subscription states
2. **SubscriptionManager**: Handles SNS subscriptions and notification delivery
3. **UserManager**: Manages IAM users, groups, and access keys
4. **NotificationManager**: Creates and sends all email notifications

### Lambda Functions

1. **Provisioner**: Creates users and initiates subscriptions
2. **SubscriptionVerifier**: Checks subscription status and manages the confirmation flow
3. **RotationHandler**: Handles credential rotation (called by AWS Secrets Manager)
4. **RotationNotifier**: Sends notifications for upcoming and completed rotations

## Key Improvements

1. **State-Based Subscription Management**:
   - Clear subscription states (PENDING, CONFIRMED, EXPIRED, MANUAL)
   - Separate tracking of different email types

2. **Explicit Email Management**:
   - Welcome emails only sent after subscription confirmation
   - Credentials emails only sent after subscription confirmation
   - Proper resending when manually resolving expired confirmations

3. **Expired Subscription Detection and Recovery**:
   - Automatic detection of expired confirmations
   - Admin notification for manual intervention
   - Manual subscription refresh API

4. **Improved Error Handling**:
   - Robust retry mechanisms
   - Comprehensive logging
   - Proper validation of ARNs and inputs

5. **Security Improvements**:
   - Input validation and sanitization
   - Secure credential handling
   - Proper retry handling with backoff

## Workflow

### New User Provisioning
1. User provisioned through Provisioner Lambda
2. SNS subscription created in PENDING state
3. User record created in DynamoDB with PENDING_CONFIRMATION status
4. User receives confirmation email from SNS

### Subscription Confirmation
1. SubscriptionVerifier runs periodically to check subscription status
2. When user confirms subscription:
   - Status updated to CONFIRMED
   - Welcome email sent
   - Credentials email sent

### Expired Confirmation
1. SubscriptionVerifier detects subscriptions >24 hours old
2. Status updated to CONFIRMATION_EXPIRED
3. Admin receives notification about expired confirmations
4. Admin can manually refresh subscription via API
5. New confirmation email sent and status set to MANUALLY_CREATED
6. Once confirmed, welcome and credentials emails are sent

### Secret Rotation
1. RotationHandler performs the rotation via AWS Secrets Manager
2. RotationNotifier sends emails about upcoming and completed rotations

## DynamoDB Schema

```json
{
  "user_name": "username",
  "email_address": "user@example.com",
  "secret_arn": "arn:aws:secretsmanager:...",
  "subscription_arn": "arn:aws:sns:...",
  "subscription_status": "PENDING_CONFIRMATION",
  "email_sent": {
    "welcome": false,
    "credentials": false,
    "rotation_notice": false
  },
  "last_subscription_action": "2025-05-10T15:30:00Z",
  "retry_count": 0,
  "last_updated": "2025-05-10T15:30:00Z"
}
```

## Environment Variables

The system requires the following environment variables for each Lambda:

- `AWS_ACCOUNT_ID`: AWS account ID
- `DYNAMODB_TABLE`: DynamoDB table name (SecretSubscriptionsv2)
- `LLM_GROUP_NAME`: IAM group name for users
- `ROTATION_HANDLER_ARN`: ARN of the RotationHandler Lambda
- `SNS_TOPIC_ARN`: ARN of the SNS topic for notifications
- `REGION`: AWS region
- `ADMIN_EMAIL`: Email for admin notifications (optional)

## Usage

### Provisioning a User

```json
{
  "user_name": "testuser",
  "email_address": "user@example.com"
}
```

### Manually Confirming a Subscription

```json
{
  "manual_confirm": true,
  "user_name": "testuser"
}
```

### Checking Subscription Status

Run the SubscriptionVerifier Lambda periodically via CloudWatch Events to check subscription status and send emails as needed.

## Deployment

To deploy this system:

1. Create the DynamoDB table with the schema described above
2. Set up the environment variables for each Lambda
3. Deploy the Lambda functions with appropriate IAM permissions
4. Configure CloudWatch Event rules to trigger the Lambdas on schedule:
   - SubscriptionVerifier: Every 5-15 minutes
   - RotationHandler: Triggered by Secrets Manager
   - RotationNotifier: Daily for upcoming rotation checks

## Implementation Notes

- Code is designed with comprehensive error handling
- Each component has clear responsibilities
- All external inputs are validated and sanitized
- Major operations use the retry_with_backoff decorator
- Timestamps are standardized in ISO format
- Extensive logging for monitoring and troubleshooting
