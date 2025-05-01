import requests
import json

# OpenSearch connection URL
base_url = 'http://localhost:9200'

print("Checking OpenSearch status and aws index...")

# Check if OpenSearch is running
try:
    response = requests.get(f"{base_url}")
    print(f"OpenSearch status: {response.status_code}")
    print(f"OpenSearch info: {response.json()}")
except Exception as e:
    print(f"Error connecting to OpenSearch: {e}")

# Check if the aws index exists
try:
    response = requests.get(f"{base_url}/aws")
    print(f"\naws index exists: {response.status_code == 200}")
    if response.status_code == 200:
        print(f"aws index info: {response.json()}")
except Exception as e:
    print(f"Error checking aws index: {e}")

# Check aws index mappings
try:
    response = requests.get(f"{base_url}/aws/_mapping")
    print(f"\naws index mapping: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error checking aws mapping: {e}")

# Check aws index data
try:
    response = requests.get(f"{base_url}/aws/_search?size=5")
    search_results = response.json()
    print(f"\naws index search results:")
    print(f"Total hits: {search_results.get('hits', {}).get('total', {}).get('value', 0)}")
    print(f"Search hits: {json.dumps(search_results.get('hits', {}).get('hits', []), indent=2)}")
except Exception as e:
    print(f"Error searching aws index: {e}")

# List all indices
try:
    response = requests.get(f"{base_url}/_cat/indices?format=json")
    print(f"\nAll indices:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error listing indices: {e}")

print("\nDebug completed") 