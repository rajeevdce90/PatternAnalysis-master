import json
import os

# File to process
file_path = 'uploads/cloudtrail.json'
file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB

print(f"Debugging file {file_path} ({file_size:.2f} MB)...")

try:
    # Read the first part of the file (up to 5MB)
    max_bytes = 5 * 1024 * 1024
    
    with open(file_path, 'rb') as f:
        data = f.read(min(max_bytes, os.path.getsize(file_path)))
    
    # Look at the first and last 1000 characters
    print(f"\nFirst 1000 characters:")
    print(data[:1000].decode('utf-8', errors='replace'))
    
    print(f"\nLast 1000 characters:")
    print(data[-1000:].decode('utf-8', errors='replace'))
    
    # Count opening and closing braces to check structure
    opening_braces = data.count(b'{')
    closing_braces = data.count(b'}')
    opening_brackets = data.count(b'[')
    closing_brackets = data.count(b']')
    
    print(f"\nBrace count in sample: Opening {{: {opening_braces}, Closing }}: {closing_braces}")
    print(f"Bracket count in sample: Opening [: {opening_brackets}, Closing ]: {closing_brackets}")
    
    # Try to parse the JSON, with detailed error info if it fails
    try:
        decoded_data = data.decode('utf-8', errors='replace')
        print("\nAttempting to parse JSON...")
        json_data = json.loads(decoded_data)
        print("JSON parsed successfully")
        
        # Print the structure
        print("\nJSON structure:")
        if isinstance(json_data, dict):
            print(f"Top level: dictionary with {len(json_data)} keys: {list(json_data.keys())}")
            for key, value in json_data.items():
                if isinstance(value, list):
                    print(f"  '{key}': list with {len(value)} items")
                    if value and len(value) > 0:
                        print(f"  First item in '{key}' is a {type(value[0]).__name__}")
                        if isinstance(value[0], dict):
                            print(f"    Keys in first item: {list(value[0].keys())}")
                elif isinstance(value, dict):
                    print(f"  '{key}': dictionary with {len(value)} keys: {list(value.keys())}")
                else:
                    print(f"  '{key}': {type(value).__name__} = {value}")
        elif isinstance(json_data, list):
            print(f"Top level: list with {len(json_data)} items")
        else:
            print(f"Top level: {type(json_data).__name__}")
        
    except json.JSONDecodeError as e:
        print(f"\nError parsing JSON: {e}")
        print(f"Error at position {e.pos}")
        print(f"Context around error (50 chars before and after):")
        start = max(0, e.pos - 50)
        end = min(len(decoded_data), e.pos + 50)
        print(f"...{decoded_data[start:end]}...")
        
except Exception as e:
    print(f"Error occurred: {e}")

print("\nDebug completed") 