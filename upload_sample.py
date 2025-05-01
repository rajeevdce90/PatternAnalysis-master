import json
import requests
import os
import io

# File to process
file_path = 'uploads/cloudtraildata.json'

# Check if file exists
if not os.path.exists(file_path):
    print(f"Error: File {file_path} not found.")
    exit(1)

# Extract a smaller sample
print(f"Reading {file_path}...")
try:
    with open(file_path, 'r') as f:
        # Read the first 1000 lines or parse a limited number of JSON objects
        data = []
        for i, line in enumerate(f):
            if i >= 1000:  # Limit to 1000 lines
                break
            try:
                # Try to parse each line as JSON
                json_obj = json.loads(line)
                data.append(json_obj)
            except json.JSONDecodeError:
                # Skip lines that aren't valid JSON
                continue
    
    print(f"Processed {len(data)} records.")
    
    # Convert data to JSON string and then to bytes
    json_data = json.dumps(data).encode('utf-8')
    
    # Create in-memory file-like object
    file_obj = io.BytesIO(json_data)
    
    # Upload the sample data
    url = 'http://localhost:5000/upload'
    files = {'file': ('cloudtraildata_sample.json', file_obj, 'application/json')}
    form_data = {
        'target_index': 'cloudtrail',
        'datatype': 'aws_logs'
    }
    
    print(f"Uploading sample to {url}...")
    response = requests.post(url, files=files, data=form_data)
    
    print(f"Status code: {response.status_code}")
    print("Response:")
    print(response.text)
    
except Exception as e:
    print(f"Error: {e}") 