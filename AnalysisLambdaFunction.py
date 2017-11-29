import io
import re
import gzip
import json
import boto3


def print_short_record(record):
    """
    Prints out an abbreviated, one-line representation of a CloudTrail record.

    :return: always False since not a real scan
    """
    print('[{timestamp}] {region}\t{ip}\t{service}:{action}'.format(
        timestamp=record['eventTime'],
        region=record['awsRegion'],
        ip=record['sourceIPAddress'],
        service=record['eventSource'].split('.')[0],
        action=record['eventName']
    ))

    return False


def deleting_logs(record):
    """
    Checks for API calls that delete logs in CloudWatch Logs or CloudTrail.

    :return: True if record matches, False otherwise
    """
    # TODO PHASE 1: If record matches, print using print_short_record and return True
    event_source = record['eventSource']
    event_name = record['eventName']
    
    if event_source in ['logs.amazonaws.com', 'cloudtrail.amazonaws.com']: 
        if event_name.startswith('Delete'):
            print_short_record(record)
            return True
    
    pass  # do nothing


instance_identifier_arn_pattern = re.compile(r'(.*?)/i\-[a-zA-Z0-9]{8,}$')

def instance_creds_used_outside_ec2(record):
    """
    Check for usage of EC2 instance credentials from outside the EC2 service.

    :return: True if record matches, False otherwise
    """
    # TODO PHASE 2: If record matches, print using print_short_record and return True
    
    identity = record['userIdentity']

    # First, check that the role type is assumed role
    role_type = identity.get('type', '')
    if role_type != 'AssumedRole':
        return False

    # Next, check that the AKID starts with 'AS'
    access_key = identity.get('accessKeyId', '')
    if not access_key.startswith('AS'):
        return False

    # Finally, check that the end of the user ARN is an instance identifier
    arn = identity.get('arn', '')
    if instance_identifier_arn_pattern.match(arn):
        print_short_record(record)
        return True

    return False
    pass  # do nothing


analysis_functions = (
    #print_short_record,
    deleting_logs,
    instance_creds_used_outside_ec2,
)


def get_records(session, bucket, key):
    """
    Loads a CloudTrail log file, decompresses it, and extracts its records.

    :param session: Boto3 session
    :param bucket: Bucket where log file is located
    :param key: Key to the log file object in the bucket
    :return: list of CloudTrail records
    """
    s3 = session.client('s3')
    response = s3.get_object(Bucket=bucket, Key=key)

    with io.BytesIO(response['Body'].read()) as obj:
        with gzip.GzipFile(fileobj=obj) as logfile:
            records = json.load(logfile)['Records']
            sorted_records = sorted(records, key=lambda r: r['eventTime']) 
            return sorted_records


def get_log_file_location(event):
    """
    Generator for the bucket and key names of each CloudTrail log 
    file contained in the event sent to this function from S3.
    (usually only one but this ensures we process them all).

    :param event: S3:ObjectCreated:Put notification event
    :return: yields bucket and key names
    """
    for event_record in event['Records']:
        bucket = event_record['s3']['bucket']['name']
        key = event_record['s3']['object']['key']
        yield bucket, key


def handler(event, context):
    # Create a Boto3 session that can be used to construct clients
    session = boto3.session.Session()
    cloudwatch = session.client('cloudwatch')

    # Get the S3 bucket and key for each log file contained in the event 
    for bucket, key in get_log_file_location(event):
        # Load the CloudTrail log file and extract its records
        print('Loading CloudTrail log file s3://{}/{}'.format(bucket, key))
        records = get_records(session, bucket, key)
        print('Number of records in log file: {}'.format(len(records)))

        # Process the CloudTrail records
        for record in records:
            for func in analysis_functions:
                if func(record):
                    # TODO PHASE 3: Put metric data to CloudWatch to trigger the alarm
                    
                    if func(record):
                        cloudwatch.put_metric_data(
                            Namespace='AWS/reInvent2017/SID341',
                            MetricData=[{
                                'MetricName': 'AnomaliesDetected',
                                'Value': 1,
                                'Unit': 'Count',
                            }]
                        )
                    
                    pass  # do nothing
