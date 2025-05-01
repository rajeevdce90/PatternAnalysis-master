import json
import io
import os
import requests

# Target index and datatype
target_index = 'aws'
datatype = 'aws_logs'

# Upload URL
url = 'http://localhost:5000/upload'

print("Creating a CloudTrail sample based on the observed format...")

try:
    # Create a sample with multiple CloudTrail records
    sample_records = [
        {
            "userAgent": "aws-cli/1.16.193 Python/2.7.16 Linux/4.4.0-039049-Microsoft botocore/1.12.183",
            "eventID": "dc025c66-2d10-437e-a036-0092db2e0187",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDA9BO36HFBHKGJAO9C1",
                "arn": "arn:aws:iam::811596193553:user/backup",
                "accountId": "811596193553",
                "accessKeyId": "AKIA01U43UX3RBRDXF4Q",
                "userName": "backup"
            },
            "eventType": "AwsApiCall",
            "sourceIPAddress": "237.5.197.10",
            "eventName": "DescribeSnapshots",
            "eventSource": "ec2.amazonaws.com",
            "recipientAccountId": "811596193553",
            "requestParameters": {
                "maxResults": 1000,
                "snapshotSet": {},
                "ownersSet": {
                    "items": [{"owner": "811596193553"}]
                },
                "sharedUsersSet": {},
                "filterSet": {}
            },
            "awsRegion": "us-west-1",
            "requestID": "8a8229ce-1ba9-4c28-a508-e4d157ccee86",
            "responseElements": None,
            "eventVersion": "1.05",
            "eventTime": "2019-07-04T10:28:25Z"
        },
        {
            "userAgent": "ec2.amazonaws.com",
            "eventID": "ef9ee142-e534-4ce5-be9c-f47d7b596808",
            "userIdentity": {
                "type": "AWSService",
                "invokedBy": "ec2.amazonaws.com"
            },
            "eventType": "AwsApiCall",
            "sourceIPAddress": "ec2.amazonaws.com",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "recipientAccountId": "811596193553",
            "requestParameters": {
                "roleSessionName": "i-aa2d3b42e5c6e801a",
                "roleArn": "arn:aws:iam::811596193553:role/flaws"
            },
            "awsRegion": "us-west-2",
            "sharedEventID": "b831205-94ae-4693-aa0d-d5500dbb2d6c",
            "requestID": "6904e27e-4bc7-430e-8b48-97e7bce22a97",
            "responseElements": {
                "credentials": {
                    "sessionToken": "AgoJb3JpZ2luX2VjEKP...[TRUNCATED]",
                    "accessKeyId": "ASIAIS762V284C5QWS1V",
                    "expiration": "Jul 4, 2019 4:29:29 PM"
                }
            },
            "eventVersion": "1.05",
            "eventTime": "2019-07-04T10:29:02Z",
            "resources": [
                {
                    "ARN": "arn:aws:iam::811596193553:role/flaws",
                    "accountId": "811596193553",
                    "type": "AWS::IAM::Role"
                }
            ]
        }
    ]
    
    # Create a CloudTrail JSON structure
    cloudtrail_data = {"Records": sample_records}
    
    # Convert to JSON string
    json_sample = json.dumps(cloudtrail_data)
    bytes_data = json_sample.encode('utf-8')
    
    # Create an in-memory file-like object
    file_obj = io.BytesIO(bytes_data)
    
    # Create the form data
    files = {'file': ('cloudtrail_sample.json', file_obj, 'application/json')}
    data = {
        'target_index': target_index,
        'datatype': datatype
    }
    
    print("Sending upload request with realistic CloudTrail sample...")
    response = requests.post(url, files=files, data=data)
    
    print(f"Status code: {response.status_code}")
    try:
        print(f"Response: {response.json()}")
    except:
        print(f"Raw response: {response.text[:1000]}")
        
except Exception as e:
    print(f"Error occurred: {e}")

print("Script completed") 