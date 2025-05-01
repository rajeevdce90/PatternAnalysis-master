import requests
import json

# OpenSearch connection URL
base_url = 'http://localhost:9200'

# CloudTrail data to upload directly - multiple records
cloudtrail_records = [
    # Second record
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
    },
    # Third record
    {
        "userAgent": "aws-cli/1.16.193 Python/3.6.8 Linux/4.4.0-1085-aws botocore/1.12.183",
        "eventID": "7b2eb10f-2afa-4d9c-b828-85f6a3daee46",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA9BO36HFBHKGJAO9C1",
            "arn": "arn:aws:iam::811596193553:user/admin",
            "accountId": "811596193553",
            "accessKeyId": "AKIA01U43UX3RBRDXF4Q",
            "userName": "admin"
        },
        "eventType": "AwsApiCall",
        "sourceIPAddress": "192.168.1.100",
        "eventName": "CreateInstance",
        "eventSource": "ec2.amazonaws.com",
        "recipientAccountId": "811596193553",
        "requestParameters": {
            "instanceType": "t2.micro",
            "imageId": "ami-12345678"
        },
        "awsRegion": "us-east-1",
        "requestID": "c4d9e871-af56-4a5d-b7e8-9d4e6c1a2b3d",
        "responseElements": {
            "instanceId": "i-0a1b2c3d4e5f67890"
        },
        "eventVersion": "1.05",
        "eventTime": "2019-07-05T08:15:30Z"
    },
    # Fourth record
    {
        "userAgent": "console.amazonaws.com",
        "eventID": "9c8d7e6f-5a4b-3c2d-1e0f-9a8b7c6d5e4f",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA9BO36HFBHKGJAO9C1",
            "arn": "arn:aws:iam::811596193553:user/developer",
            "accountId": "811596193553",
            "accessKeyId": "AKIA01U43UX3RBRDXF4Q",
            "userName": "developer"
        },
        "eventType": "AwsConsoleSignIn",
        "sourceIPAddress": "203.0.113.10",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "recipientAccountId": "811596193553",
        "requestParameters": None,
        "awsRegion": "us-east-1",
        "requestID": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
        "responseElements": {
            "ConsoleLogin": "Success"
        },
        "eventVersion": "1.05",
        "eventTime": "2019-07-05T12:45:22Z"
    }
]

print(f"Attempting to upload {len(cloudtrail_records)} additional CloudTrail records directly to OpenSearch...")

# Upload each record individually
success_count = 0
for i, record in enumerate(cloudtrail_records):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{base_url}/aws/_doc", 
            data=json.dumps(record),
            headers=headers
        )
        
        if response.status_code == 201:
            success_count += 1
            print(f"Record {i+1} uploaded successfully: {response.json()['_id']}")
        else:
            print(f"Failed to upload record {i+1}: {response.status_code}")
            
    except Exception as e:
        print(f"Error uploading record {i+1}: {e}")

# Refresh the index
try:
    refresh_response = requests.post(f"{base_url}/aws/_refresh")
    print(f"Refresh status: {refresh_response.status_code}")
except Exception as e:
    print(f"Error refreshing index: {e}")

# Get updated count
try:
    search_response = requests.get(f"{base_url}/aws/_search?size=0")
    search_results = search_response.json()
    total_hits = search_results.get('hits', {}).get('total', {}).get('value', 0)
    print(f"\nTotal documents in aws index: {total_hits}")
except Exception as e:
    print(f"Error getting document count: {e}")

print(f"Upload completed: {success_count} of {len(cloudtrail_records)} records successfully uploaded") 