import base64
import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr
from os import getenv
from uuid import uuid4
import json

region_name = getenv('APP_REGION')
blog_user_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogUser')


def lambda_handler(event, context):
    # print("Received event:", event)
    http_method = event["httpMethod"]
    # print(http_method)
    # If the user is not authenticated, they can only create a user
    if http_method == "POST" or http_method == "post":
        return create_user(event, context)

    # grab the auth header and decode it
    auth_header = event["headers"]["Authorization"]
    if not auth_header:
        return response(401, "Unauthorized")
    encoded_credentials = auth_header.split(' ')[1]
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')

    # Get the user's guid from the decoded credentials
    current_user_id = get_user_by_username_password(decoded_credentials.split(":")[0], decoded_credentials.split(":")[1])
    # print("Received event: " + json.dumps(event, indent=2))
    # current_user_id = event['requestContext']['authorizer']['user_id']
    # We only need to check the remaining http methods if the user is authenticated, we can do that here once.
    # if current_user_id is None:
    #     return response(401, "Unauthorized")

    if http_method == "GET":
        return get_user(event, context)
    if http_method == "PUT":
        return update_user(event, context, current_user_id)
    if http_method == "DELETE":
        return delete_user(current_user_id)
    # else:
    return response(400, "invalid http method")
    # else:   # This should never happen, but it's good to have a catch-all
    #     return response(500, "Internal Server Error")


# Anyone can create a user, no need for authentication
def create_user(event, context):
    if "body" in event and event["body"] is not None:
        event = json.loads(event["body"])

    # Check if username already exists in the table
    user = blog_user_table.scan(FilterExpression=Attr('username').eq(event["username"]))
    if len(user["Items"]) > 0:
        return response(400, {"error": "Username already exists"})

    # Generate a new guid for the user
    user_id = str(uuid4())
    # Grab the username and password from the request body
    username = event["username"]
    password = event["password"]

    # check if the username or password is empty
    if username is None or password is None:
        return response(400, {"error": "Username and password are required"})

    # Check if the username is already taken???
    blog_user_table.put_item(Item={
        "Id": user_id,
        "username": username,
        "password": password
    })

    return response(200, {"user_id": user_id, "message": "User successfully created!"})


# Grabs the current users guid with their auth credentials
def get_user_by_username_password(username, password):
    # find the user in the table
    user = blog_user_table.scan(FilterExpression=Attr('username').eq(username) & Attr('password').eq(password))
    # if the user is found, return their guid
    if len(user["Items"]) == 1:
        return user["Items"][0]["Id"]
    # if the user is not found, return None
    else:
        return None


# This endpoint is only accessible by users of the website, returns the user's username and id.
def get_user(event, context):
    path = event.get("pathParameters") or {}

    # Now, even if pathParameters were None, path will be an empty dict,
    # and the 'in' checks will not raise an error
    if "id" in path:
        user_id = path["id"]
        # Fetch the user data from the table. Make sure to handle potential exceptions here.
        user_data = blog_user_table.get_item(Key={"Id": user_id})
        # Check if the user was found
        if "Item" not in user_data:
            return response(404, {"error": f"User with id {user_id} not found"})
        user = user_data["Item"]
        # Construct a response that only includes the user_id and username
        user_info = {
            "user_id": user_id,
            "username": user.get("username", "No username")  # Provide a default value in case the username is not found
        }
        return response(200, user_info)

    elif "username" in path:
        username = path["username"]
        # Fetch the user data from the table. Make sure to handle potential exceptions here.
        user_data = blog_user_table.scan(FilterExpression=Attr("username").eq(username))
        # Check if the user was found
        if len(user_data["Items"]) == 0:
            return response(404, {"error": f"User with username {username} not found"})
        user = user_data["Items"][0]
        # Construct a response that only includes the user_id and username
        user_info = {
            "user_id": user["Id"],
            "username": user.get("username", "No username")  # Provide a default value in case the username is not found
        }
        return response(200, user_info)

    # If no path parameters are provided, return a list of all users
    users = blog_user_table.scan()["Items"]
    simplified_users = [{"username": user.get("username"), "Id": user.get("Id")} for user in users]
    return response(200, simplified_users)


#   Only the user can update their own account, we grab their guid by get_user_by_username_password(username, password):
def update_user(event, context, user_id):
    if "body" in event and event["body"] is not None:
        event = json.loads(event["body"])

    username = event["username"]
    password = event["password"]

    user = blog_user_table.get_item(Key={"Id": user_id})["Item"]

    if username is not None:
        user['username'] = username
    if password is not None:
        user['password'] = password

    blog_user_table.put_item(Item=user)

    return response(200, user)


# Only the user can delete their own account, we grab their guid by get_user_by_username_password(username, password):
def delete_user(user_id):
    output = blog_user_table.delete_item(Key={"Id": user_id})
    return response(200, output)


def response(code, body):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body),
        "isBase64Encoded": False
    }
