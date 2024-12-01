import json

import boto3
import requests
from rich import print as rich_print
from rich.tree import Tree

access_key = ""
secret_key = ""
region = "us-east-2"

def get_role_name(client, instance_arn, permission_set_arn):
    response = client.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    )
    return response['PermissionSet']['Name']

def list_groups(client, identity_store_id):
    groups = []
    paginator = client.get_paginator('list_groups')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups.extend(page['Groups'])
    return groups

def list_permission_sets(client, instance_arn):
    permission_sets = []
    paginator = client.get_paginator('list_permission_sets')
    for page in paginator.paginate(InstanceArn=instance_arn):
        permission_sets.extend(page['PermissionSets'])
    return permission_sets

def list_accounts_with_permission_set(client, instance_arn, permission_set_arn):
    account_ids = []
    paginator = client.get_paginator('list_accounts_for_provisioned_permission_set')
    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    ):
        account_ids.extend(page['AccountIds'])
    return account_ids

def list_users_with_permission_set(client, instance_arn, account_id, permission_set_arn):
    assignments = []
    paginator = client.get_paginator('list_account_assignments')
    for page in paginator.paginate(
        InstanceArn=instance_arn,
        AccountId=account_id,
        PermissionSetArn=permission_set_arn
    ):
        assignments.extend(page['AccountAssignments'])
    return assignments

identity_store_client = boto3.client(
    'identitystore',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name=region
)

sso_client = boto3.client(
    'sso-admin',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key,
    region_name=region
)

sso_instance = sso_client.list_instances()['Instances'][0]
sso_instance_arn = sso_instance['InstanceArn']
sso_identity_store_id = sso_instance['IdentityStoreId']

users = identity_store_client.list_users(IdentityStoreId=sso_identity_store_id)['Users']
sso_users = {user['UserId']: user['UserName'] for user in users}

# def list_users(aws_access_key_id, aws_secret_access_key, identity_store_id, region):
#         credentials = botocore.credentials.Credentials(
#         access_key=aws_access_key_id,
#         secret_key=aws_secret_access_key
#     )
    
#     sigv4 = SigV4Auth(credentials, 'identitystore', region)
#     endpoint = f'https://up.sso.{region}.amazonaws.com/identitystore/'
#     headers = {
#     'Content-Type': 'application/x-amz-json-1.1',
#     'X-Amz-Target': 'AWSIdentityStoreService.SearchUsers'
#     }

#     all_results = []
    
#     next_token = None
#     while True:
#         data = json.dumps({"IdentityStoreId": identity_store_id, "MaxResults": 100, "NextToken": next_token})
#         request = AWSRequest(method='POST', url=endpoint, data=data, headers=headers)
#         sigv4.add_auth(request)
#         prepped = request.prepare()
    
#         response = requests.post(prepped.url, headers=prepped.headers, data=data)
#         response_data = response.json()
    
#         all_results.extend(response_data.get('Users', []))
    
#         next_token = response_data.get('NextToken')
#         if not next_token:
#             break
    
#     return all_results

# users = list_users(
#     access_key,
#     secret_key,
#     sso_identity_store_id,
#     region
# )

groups = list_groups(identity_store_client, sso_identity_store_id)

group_tracker = {group['GroupId']: set() for group in groups}
for group in groups:
    group_memberships = identity_store_client.list_group_memberships(
        IdentityStoreId=sso_identity_store_id,
        GroupId=group['GroupId']
    )
    for membership in group_memberships['GroupMemberships']:
        user_id = membership['MemberId']['UserId']
        group_tracker[group['GroupId']].add(sso_users[user_id])

aws_access_tracker = {}
permissions_sets = list_permission_sets(sso_client, sso_instance_arn)

for permission_set in permissions_sets:
    role_name = get_role_name(sso_client, sso_instance_arn, permission_set)
    accounts = list_accounts_with_permission_set(sso_client, sso_instance_arn, permission_set)
    for account in accounts:
        permission_assignments = list_users_with_permission_set(sso_client, sso_instance_arn, account, permission_set)
        for assignment in permission_assignments:
            principal_id = assignment['PrincipalId']
            if assignment['PrincipalType'] == 'GROUP':
                users_in_group = group_tracker[principal_id]
            else:
                users_in_group = {sso_users[principal_id]}

            if account not in aws_access_tracker:
                aws_access_tracker[account] = {}
            if role_name not in aws_access_tracker[account]:
                aws_access_tracker[account][role_name] = set()
            aws_access_tracker[account][role_name].update(users_in_group)

for account, roles in aws_access_tracker.items():
    for role, users in roles.items():
        aws_access_tracker[account][role] = sorted(users)

def build_rich_tree(data, root):
    for key, value in data.items():
        branch = root.add(f"[bold cyan]{key}[/bold cyan]")
        if isinstance(value, dict):
            build_rich_tree(value, branch)
        else:
            for user in value:
                branch.add(f"[green]{user}[/green]")

aws_tree = Tree("[bold magenta]AWS Identity Center Access Tracker[/bold magenta]")
build_rich_tree(aws_access_tracker, aws_tree)
rich_print(aws_tree)