import json
import base64
import boto3
from base64 import b64decode
import os

# Initialize DynamoDB resource
region_name = os.getenv('APP_REGION')
blog_user_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogUser')


def lambda_handler(event, context):
    # Retrieve the token from the event
    token = event['authorizationToken']

    # Ensure the token starts with "Basic "
    if not token.startswith("Basic "):
        return generate_deny_policy()

    # Remove "Basic " prefix and decode the remaining Base64 token
    encoded_credentials = token[6:]
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')

    # Split the decoded credentials into username and password
    username, password = decoded_credentials.split(':', 1)

    user_id, effect = found_in_db(username, password)
    if effect == "Allow":
        return generate_allow_policy(user_id)
    else:
        return generate_deny_policy()

    # except Exception as e:
    #     print(f"Error: {str(e)}")
    #     return generate_deny_policy()


def found_in_db(username, password):
    response = blog_user_table.scan(
        FilterExpression="username = :username AND password = :password",
        ExpressionAttributeValues={
            ':username': username,
            ':password': password
        }
    )

    if len(response["Items"]) == 1:
        user_id = response["Items"][0].get("Id")
        return user_id, "Allow"
    else:
        return None, "Deny"


def generate_allow_policy(user_id):
    return {
        "principalId": user_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ]
        }
        # ,
        # "context": {
        #     "user_id": user_id
        # }
    }


def generate_deny_policy():
    return {
        "principalId": "UnauthorizedUser",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": "*"
                }
            ]
        }
    }
