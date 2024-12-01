# AWS Identity Center Access Tracker

This project is all about tracking who has access to what within AWS Identity Center (formerly AWS Single Sign-On). The script scrapes AWS Identity Center to determine which users and groups have been assigned to specific roles in different AWS accounts. It provides a comprehensive view of access across the organization, making it easier to manage and audit permissions without endless clicking through the AWS console.

## Features
- **List AWS Identity Center Groups**: Collects all groups defined in AWS Identity Center.
- **List Permissions Sets**: Gathers all permission sets created and assigned to users or groups.
- **Track Account Assignments**: Maps permission sets to specific accounts and shows which users or groups have been granted access.
- **User-Friendly Output**: Utilizes `Rich` for console output, providing a pretty visualization of access details.

## Prerequisites
- Python 3.8+
- AWS credentials with sufficient permissions to call AWS Identity Store and SSO APIs (details below).
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone this repository:
   ```bash
   git clone <repo-url>
   cd aws-identity-center-access-tracker
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up your AWS credentials using environment variables or your preferred method (e.g., AWS CLI profiles).

## Configuration
To connect to AWS, update the following values in the script:

- **Access Keys**: Replace `access_key` and `secret_key` variables in `main.py` with your credentials or use environment variables for security.
- **Region**: Set the `region` variable, e.g., `us-east-2`.

**Permissions**: Ensure your AWS user has the following permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "identitystore:ListUsers",
                "identitystore:ListGroups",
                "identitystore:ListGroupMemberships",
                "sso:SearchUsers",
                "sso:ListInstances",
                "sso:ListPermissionSets",
                "sso:DescribePermissionSet",
                "sso:ListAccountsForProvisionedPermissionSet",
                "sso:ListAccountAssignments",
                "sso-directory:SearchUsers"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage
Run the script to collect AWS Identity Center data:

```bash
python main.py
```

This will fetch all users, groups, permissions sets, and their relationships, and then output them in a neat, readable tree structure using Rich.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Acknowledgments
Thank you to the readers of my Medium articles!