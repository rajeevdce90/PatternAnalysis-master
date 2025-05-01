import requests
import json
import io
import os

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
    # Load the first chunk of the file to extract a sample
    max_bytes = 1024 * 1024  # 1MB max to avoid memory issues
    
    with open(file_path, 'rb') as f:
        data = f.read(max_bytes)
    
    # Try to parse the data as JSON
    try:
        json_data = json.loads(data.decode('utf-8', errors='ignore'))
        
        # Check if the structure has a 'Records' array
        if 'Records' in json_data and isinstance(json_data['Records'], list):
            records = json_data['Records']
            # Take the first 10 records
            sample_records = records[:10]
            print(f"Extracted {len(sample_records)} records from the file")
            
            # Create a sample JSON with the same structure
            sample_data = {"Records": sample_records}
            json_sample = json.dumps(sample_data)
            bytes_data = json_sample.encode('utf-8')
            
            # Create an in-memory file-like object
            file_obj = io.BytesIO(bytes_data)
            
            # Create the form data
            files = {'file': ('cloudtrail_sample.json', file_obj, 'application/json')}
            data = {
                'target_index': target_index,
                'datatype': datatype
            }
            
            print("Sending upload request...")
            response = requests.post(url, files=files, data=data)
            
            print(f"Status code: {response.status_code}")
            try:
                print(f"Response: {response.json()}")
            except:
                print(f"Raw response: {response.text[:1000]}")
        else:
            print("The file doesn't have the expected 'Records' array structure")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        print("The file might be too large or not a valid JSON")
        
except Exception as e:
    print(f"Error occurred: {e}")

print("Script completed") 