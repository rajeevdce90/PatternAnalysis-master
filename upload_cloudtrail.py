import requests
import os
import sys
import time

# File to upload
file_path = 'uploads/cloudtrail.json'
file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB

# Target index and datatype
target_index = 'aws'
datatype = 'aws_logs'

# Upload URL
url = 'http://localhost:5000/upload'

print(f"Starting upload of {file_path} ({file_size:.2f} MB) to {url}...")
print(f"Target index: {target_index}, Datatype: {datatype}")

try:
    start_time = time.time()
    
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f, 'application/json')}
        data = {
            'target_index': target_index,
            'datatype': datatype
        }
        
        print("Sending request...")
        response = requests.post(url, files=files, data=data)
        
        elapsed_time = time.time() - start_time
        print(f"Upload completed in {elapsed_time:.2f} seconds")
        print(f"Status code: {response.status_code}")
        
        try:
            json_response = response.json()
            print(f"Response: {json_response}")
        except Exception as e:
            print(f"Could not parse JSON response: {e}")
            print(f"Raw response: {response.text[:1000]}...")
            
except Exception as e:
    print(f"Error occurred: {e}")
    sys.exit(1)

print("Upload script completed") 