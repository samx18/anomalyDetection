import json
import random
import string
from time import sleep

import boto3
import botocore


def handler(event, context):
    resource_name = 'ReInvent2017-SID341-{}'.format(
        ''.join(random.choice(string.ascii_lowercase) for _ in range(5)))

    # Create a log group CloudWatch Logs
    logs = boto3.client('logs')
    logs.create_log_group(logGroupName=resource_name)
    
    # Create a trail in CloudTrail
    cloudtrail = boto3.client('cloudtrail')
    cloudtrail.create_trail(Name=resource_name, S3BucketName='reinvent2017-sid341-activitygenbucket-aa7ibwm3vr46')

    s3 = boto3.client('s3')
    try:
        # Fetch the "exfiltrated" instance credentials from the S3 bucket
        creds_json = s3.get_object(Bucket='reinvent2017-sid341-activitygenbucket-aa7ibwm3vr46', Key='creds.txt')['Body'].read()
        creds = json.loads(creds_json)

        # Create a new Boto client using the instance credentials
        cred_client = boto3.client('s3',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['Token'],
        )
        
        # Make calls using the instance credentials
        res = cred_client.list_objects(Bucket='reinvent2017-sid341-activitygenbucket-aa7ibwm3vr46')
        print(res)
        res = cred_client.get_bucket_policy(Bucket='reinvent2017-sid341-activitygenbucket-aa7ibwm3vr46')
        print(res)
    except botocore.exceptions.ClientError as e:
        print(e)
        
    # Sleep for a bit
    sleep(random.randint(10, 30))
    
    cloudtrail.stop_logging(Name=resource_name)
    
    # Sleep for a bit
    sleep(random.randint(10, 30))
    
    # Delete the log group and trail
    logs.delete_log_group(logGroupName=resource_name)
    cloudtrail.delete_trail(Name=resource_name)
