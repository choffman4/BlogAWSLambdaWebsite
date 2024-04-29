import boto3
import base64
from boto3.dynamodb.conditions import Key, Attr
from os import getenv
from uuid import uuid4
import json

region_name = getenv('APP_REGION')
blog_blog_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogBlog')
blog_user_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogUser')
blog_post_table = boto3.resource('dynamodb', region_name=region_name).Table('BlogPost')


#   This lambda will be locked down to only authenticated users, so we don't need to check for that here,
#   but we still need to check the http method
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

    if http_method == "GET":
        return get_blog(event, context)
    if http_method == "POST":
        return create_blog(event, context, current_user_id)
    if http_method == "PUT":
        return update_blog(event, context, current_user_id)
    if http_method == "DELETE":
        return delete_blog(event, context, current_user_id)
    else:
        return response(400, "invalid http method")


def create_blog(event, context, user_id):
    body = None
    if "body" in event and event["body"] is not None:
        body = json.loads(event["body"])

    # user_id = event['requestContext']['authorizer']['lambda']['user_id']

    blog_id = str(uuid4())
    title = body["title"]
    category = body["category"]
    description = body["description"]

    blog_blog_table.put_item(Item={
        "Id": blog_id,
        "author": user_id,
        "title": title,
        "category": category,
        "description": description,
        "subscribers": []
    })

    return response(200, {"blog_id": blog_id, "message": "Blog successfully created!"})


def get_blog(event, context):
    print("event:", event)
    path = event["pathParameters"]
    print("path:", path)
    if path is None:
        blogs = blog_blog_table.scan()["Items"]
        blogs = sorted(blogs, key=lambda x: len(x['subscribers']))
        return response(200, blogs)

    if "id" in path:
        blog_id = path["id"]
        blog = blog_blog_table.scan(FilterExpression=Attr("Id").eq(blog_id))
        return response(200, blog)
    if "title" in path:
        title = path["title"]
        blog = blog_blog_table.scan(FilterExpression=Attr('title').eq(title))
        return response(200, blog)
    if "category" in path:
        category = path["category"]
        blog = blog_blog_table.scan(FilterExpression=Attr('category').eq(category))
        return response(200, blog)
    if "author" in path:
        author = path["author"]
        blog = blog_blog_table.scan(FilterExpression=Attr('user_id').eq(author))
        return response(200, blog)
    if "blog_id" in path:
        blog_id = path["blog_id"]
        # find all the posts for the blog
        posts = blog_post_table.scan(FilterExpression=Attr('blog_id').eq(blog_id))["Items"]
        return response(200, posts)


def update_blog(event, context, user_id):
    # user_id = event['requestContext']['authorizer']['lambda']['user_id']
    if user_id is None:
        return response(401, "Unauthorized")

    if "body" in event and event["body"] is not None:
        event = json.loads(event["body"])

    title = event["title"]
    category = event["category"]
    description = event["description"]
    blog_id = event["id"]

    if blog_id is None:
        return response(400, "Blog id not found")

    blog = blog_blog_table.get_item(Key={"Id": blog_id})["Item"]
    if blog is None:
        return response(400, "Blog not found")

    if blog['author'] == user_id:
        if title != "":
            blog['title'] = title
        if category != "":
            blog['category'] = category
        if description != "":
            blog['description'] = description

        blog_blog_table.put_item(Item=blog)

        return response(200, blog)

    blog['subscribers'].append(user_id)
    blog_blog_table.put_item(Item=blog)
    return response(200, blog)


def delete_blog(event, context, user_id):
    if "pathParameters" not in event:
        return response(400, {"error": "no path params"})
    path = event["pathParameters"]
    if path is None or "id" not in path:
        return response(400, "no id found")
    # user_id = event['requestContext']['authorizer']['lambda']['user_id']
    blog_id = path["id"]

    try:
        blog = blog_blog_table.get_item(Key={"Id": blog_id})["Item"]
    except KeyError:
        return response(400, "Blog not found")

    # if blog is None:
    #     return response(400, "Blog not found")

    if blog['author'] != user_id:
        return response(401, "Unauthorized")

    output = blog_blog_table.delete_item(Key={"Id": blog_id})

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
