import boto3
import base64
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr
from os import getenv
from uuid import uuid4
import json
from datetime import datetime

client = boto3.client('sqs')
queue_url = getenv('QUEUE_URL')


region_name = getenv('APP_REGION')
blog_post_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogPost')
blog_blog_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogBlog')
blog_user_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogUser')


def lambda_handler(event, context):
    http_method = event["httpMethod"]

    # grab the auth header and decode it
    auth_header = event["headers"]["Authorization"]
    if not auth_header:
        return response(401, "Unauthorized")
    encoded_credentials = auth_header.split(' ')[1]
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')

    current_user_id = get_user_by_username_password(decoded_credentials.split(":")[0],
                                                    decoded_credentials.split(":")[1])

    if http_method == "POST":
        return create_post(event, context, current_user_id)
    elif http_method == "GET":
        return get_post(event, context)
    elif http_method == "PUT":
        return update_post(event, context, current_user_id)
    elif http_method == "DELETE":
        return delete_post(event, context, current_user_id)
    else:
        return response(400, "invalid http method")


def create_post(event, context, user_id):
    if "body" in event and event["body"] is not None:
        body = json.loads(event["body"])

    # grab the blog_id from the path parameters
    blog_id = body["blog_id"]

    # check if the blog_id exists
    blog = blog_blog_table.get_item(Key={"Id": blog_id})
    if "Item" not in blog:
        return response(400, "Blog not found")

    # check if the user is the author of the blog
    if blog["Item"]["author"] != user_id:
        return response(401, "Unauthorized")

    post_id = str(uuid4())
    title = body["title"]
    content = body["content"]

    blog_post_table.put_item(Item={
        "Id": post_id,
        "blog_id": blog_id,
        # "user_id": user_id,
        "title": title,
        "content": content
    })

    print("QueueURL: ", queue_url)
    date_time = datetime.now()
    message = client.send_message(
        QueueUrl=queue_url,
        MessageBody=("This was sent onnnn: " + str(date_time.strftime('%Y-%m-%d %H:%M:%S') + 'by alex'))
        )

    return response(200, {"post_id": post_id, "message": "Post successfully created!"})


def get_post(event, context):
    if "pathParameters" not in event:
        return response(400, {"error": "no path params"})

    path = event["pathParameters"]

    if path is None or "id" not in path:
        return response(400, "no id found")

    post_id = path["id"]

    post = blog_post_table.get_item(Key={"Id": post_id})["Item"]

    return response(200, post)


def update_post(event, context, user_id):
    if "body" in event and event["body"] is not None:
        body = json.loads(event["body"])

    post_id = body["post_id"]
    if post_id is None:
        return response(404, "Post_id not found")

    # check if the post_id exists
    post = blog_post_table.get_item(Key={"Id": post_id})["Item"]
    if post is None:
        return response(400, "Post not found")

    # grab the blog_id from the post
    blog_id = post["blog_id"]

    # check if the user is the author of the blog
    blog = blog_blog_table.get_item(Key={"Id": blog_id})
    if blog["Item"]["author"] != user_id:
        return response(401, "Unauthorized")

    title = body["title"]
    content = body["content"]

    if title != "":
        post['title'] = title
    if content != "":
        post['content'] = content

    blog_post_table.put_item(Item=post)

    return response(200, post)


def delete_post(event, context, user_id):
    if "pathParameters" not in event:
        return response(400, {"error": "no path params"})

    path = event["pathParameters"]

    if path is None or "id" not in path:
        return response(400, "no post_id found")

    post_id = path["id"]

    # check if the post_id exists
    post = blog_post_table.get_item(Key={"Id": post_id})["Item"]
    if post is None:
        return response(400, "Post not found")

    # grab the blog_id from the post
    blog_id = post["blog_id"]

    # check if the user is the author of the blog
    blog = blog_blog_table.get_item(Key={"Id": blog_id})
    if blog["Item"]["author"] != user_id:
        return response(401, "Unauthorized")

    output = blog_post_table.delete_item(Key={"Id": post_id})

    return response(200, output)


def get_user_by_username_password(username, password):
    # find the user in the table
    user = blog_user_table.scan(FilterExpression=Attr('username').eq(username) & Attr('password').eq(password))
    # if the user is found, return their guid
    if len(user["Items"]) == 1:
        return user["Items"][0]["Id"]
    # if the user is not found, return None
    else:
        return None


def response(code, body):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(body),
        "isBase64Encoded": False
    }
