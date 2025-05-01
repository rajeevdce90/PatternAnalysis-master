import requests
import json

# OpenSearch connection URL
base_url = 'http://localhost:9200'

# CloudTrail data to upload directly
cloudtrail_data = {
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
}

print("Attempting to upload CloudTrail data directly to OpenSearch...")

# Upload data directly to the aws index
try:
    headers = {'Content-Type': 'application/json'}
    response = requests.post(
        f"{base_url}/aws/_doc", 
        data=json.dumps(cloudtrail_data),
        headers=headers
    )
    
    print(f"Upload status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Refresh the index to make the document immediately available for search
    refresh_response = requests.post(f"{base_url}/aws/_refresh")
    print(f"Refresh status: {refresh_response.status_code}")
    
    # Check if the document is searchable
    search_response = requests.get(f"{base_url}/aws/_search")
    search_results = search_response.json()
    print(f"\nSearch results after direct upload:")
    print(f"Total hits: {search_results.get('hits', {}).get('total', {}).get('value', 0)}")
    print(f"First hit: {json.dumps(search_results.get('hits', {}).get('hits', [])[0] if search_results.get('hits', {}).get('hits', []) else 'No results', indent=2)}")
    
except Exception as e:
    print(f"Error during direct upload: {e}")

print("Direct upload script completed") 