import json
import io
import os
import requests

# File to process
file_path = 'uploads/cloudtrail.json'
file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB

# Target index and datatype
target_index = 'aws'
datatype = 'aws_logs'

# Upload URL
url = 'http://localhost:5000/upload'

print(f"Processing file {file_path} ({file_size:.2f} MB)...")

try:
    # Create a simple test record in CloudTrail format
    test_record = {
        "Records": [
            {
                "eventVersion": "1.05",
                "eventTime": "2023-01-01T12:00:00Z",
                "eventSource": "test.amazonaws.com",
                "eventName": "TestEvent",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "TEST123456789",
                    "arn": "arn:aws:iam::123456789012:user/testuser",
                    "accountId": "123456789012",
                    "accessKeyId": "AKIATESTKEY12345",
                    "userName": "testuser"
                },
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.168.1.1",
                "requestParameters": {
                    "param1": "value1",
                    "param2": "value2"
                },
                "responseElements": {
                    "result": "success"
                }
            }
        ]
    }
    
    # Convert to JSON string
    json_sample = json.dumps(test_record)
    bytes_data = json_sample.encode('utf-8')
    
    # Create an in-memory file-like object
    file_obj = io.BytesIO(bytes_data)
    
    # Create the form data
    files = {'file': ('cloudtrail_sample.json', file_obj, 'application/json')}
    data = {
        'target_index': target_index,
        'datatype': datatype
    }
    
    print("Sending upload request with test CloudTrail record...")
    response = requests.post(url, files=files, data=data)
    
    print(f"Status code: {response.status_code}")
    try:
        print(f"Response: {response.json()}")
    except:
        print(f"Raw response: {response.text[:1000]}")
        
except Exception as e:
    print(f"Error occurred: {e}")

print("Script completed") 