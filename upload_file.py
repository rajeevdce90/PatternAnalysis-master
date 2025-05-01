import requests
import os

# File to upload
file_path = 'uploads/cloudtraildata.json'

# Check if file exists
if not os.path.exists(file_path):
    print(f"Error: File {file_path} not found.")
    exit(1)

# Upload parameters
url = 'http://localhost:5000/upload'
files = {'file': open(file_path, 'rb')}
data = {
    'target_index': 'cloudtrail',
    'datatype': 'aws_logs'
}

print(f"Uploading {file_path} to {url}...")
print(f"Index: cloudtrail, Datatype: aws_logs")

try:
    # Make the POST request
    response = requests.post(url, files=files, data=data)
    
    # Display the response
    print(f"Status code: {response.status_code}")
    print("Response:")
    print(response.text)
    
except Exception as e:
    print(f"Error during upload: {e}")
finally:
    # Close the file
    files['file'].close() 