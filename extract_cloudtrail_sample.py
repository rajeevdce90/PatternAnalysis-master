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
    # Read just enough of the file to get a complete JSON object
    start_marker = b'{"Records":['
    record_marker = b'{"userAgent":'  # Each record seems to start with this
    
    # Read the first chunk to ensure we get at least one complete record
    chunk_size = 50 * 1024  # 50KB chunks
    
    with open(file_path, 'rb') as f:
        # Read the header portion
        header = f.read(len(start_marker))
        if header != start_marker:
            print(f"File doesn't start with expected marker. Found: {header}")
            exit(1)
        
        print("Found valid file header")
        
        # Get first few records
        records = []
        record_count = 0
        max_records = 10
        
        # Buffer to accumulate data
        buffer = b""
        
        # Keep reading chunks until we have enough records
        while record_count < max_records:
            chunk = f.read(chunk_size)
            if not chunk:
                break
                
            buffer += chunk
            
            # Find all record markers in this chunk
            while buffer.find(record_marker) >= 0 and record_count < max_records:
                marker_pos = buffer.find(record_marker)
                
                # If we already have data in records, the previous record is complete
                if records and marker_pos > 0:
                    # Complete the previous record
                    if records[-1].endswith(b','):
                        records[-1] = records[-1][:-1]  # Remove trailing comma
                
                # If this is not the first marker, extract everything up to this marker as a record
                if record_count > 0 and marker_pos > 0:
                    record_data = buffer[:marker_pos]
                    if record_data.endswith(b','):
                        record_data = record_data[:-1]  # Remove trailing comma
                    records.append(record_data)
                
                # Start a new record
                buffer = buffer[marker_pos:]
                record_count += 1
        
        print(f"Extracted {len(records)} record markers")
        
        # Process the records
        processed_records = []
        for i, record_data in enumerate(records):
            try:
                # Make sure the record is valid JSON
                if record_data.startswith(b'{') and (record_data.endswith(b'}') or record_data.endswith(b'},')):
                    # Remove trailing comma if it exists
                    if record_data.endswith(b','):
                        record_data = record_data[:-1]
                        
                    # Add to processed records
                    try:
                        json_record = json.loads(record_data)
                        processed_records.append(json_record)
                        print(f"Successfully processed record {i+1}")
                    except json.JSONDecodeError as e:
                        print(f"Error parsing record {i+1}: {e}")
                else:
                    print(f"Record {i+1} doesn't seem to be a valid JSON object")
            except Exception as e:
                print(f"Error processing record {i+1}: {e}")
        
        print(f"Successfully processed {len(processed_records)} records")
        
        if processed_records:
            # Create a JSON structure for the sample
            sample_data = {"Records": processed_records}
            
            # Convert to JSON string and then to bytes
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
            print("No records were successfully processed")
except Exception as e:
    print(f"Error occurred: {e}")

print("Script completed") 