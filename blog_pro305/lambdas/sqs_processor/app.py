import json
import boto3
from os import getenv
from datetime import datetime

bucket_name = getenv('BUCKET_NAME')
s3_client = boto3.client('s3')


def lambda_handler(event, context):
    for message in event['Records']:
        process_message(message)
        s3_message = {
            "message": "Notification processed successfully!",
            "messageBody": message,
            "timestamp": datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        }
        post_log_to_s3(s3_message)

    print("done")


def post_log_to_s3(log_message):
    log_file_name = f'log-{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.txt'
    s3_client.put_object(
        Bucket=bucket_name,
        Key=log_file_name,
        Body=json.dumps(log_message)  # Convert the dictionary to a JSON string
    )


def process_message(message):
    try:
        print(f'here is the message in the body: {message['body']}')
    except Exception as err:
        print("An error occurrred")
        raise err