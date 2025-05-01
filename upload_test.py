import requests
import json
import io

# Create a simple valid JSON sample
test_data = {
    "testEvent": {
        "eventSource": "test.amazonaws.com",
        "eventName": "TestEvent",
        "eventTime": "2023-01-01T12:00:00Z",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "testuser"
        },
        "awsRegion": "us-east-1"
    }
}

# Target index and datatype
target_index = 'aws'
datatype = 'aws_logs'

# Upload URL
url = 'http://localhost:5000/upload'

# Convert data to JSON string then to bytes
json_data = json.dumps(test_data)
bytes_data = json_data.encode('utf-8')

# Create an in-memory file-like object
file_obj = io.BytesIO(bytes_data)

# Create the form data
files = {'file': ('test.json', file_obj, 'application/json')}
data = {
    'target_index': target_index,
    'datatype': datatype
}

print("Sending test upload request...")
try:
    response = requests.post(url, files=files, data=data)
    print(f"Status code: {response.status_code}")
    try:
        print(f"Response: {response.json()}")
    except:
        print(f"Raw response: {response.text[:1000]}")
except Exception as e:
    print(f"Error: {e}")

print("Test completed") 