import os

# File to process
file_path = 'uploads/cloudtrail.json'
file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB

print(f"Examining file {file_path} ({file_size:.2f} MB)...")

# Read the first part of the file to understand its structure
try:
    with open(file_path, 'rb') as f:
        # Read the first 2KB of the file
        data = f.read(2048)
        print("\nFirst 2KB of the file (showing first 500 chars):")
        print(data[:500])
        
        # Try to decode as UTF-8
        try:
            decoded = data.decode('utf-8')
            print("\nDecoded as UTF-8 (showing first 500 chars):")
            print(decoded[:500])
        except UnicodeDecodeError:
            print("\nFailed to decode as UTF-8")
        
        # Try to decode as Latin-1 (should always work)
        decoded_latin = data.decode('latin-1')
        print("\nDecoded as Latin-1 (showing first 500 chars):")
        print(decoded_latin[:500])
        
except Exception as e:
    print(f"Error occurred: {e}")

print("\nExamination completed") 