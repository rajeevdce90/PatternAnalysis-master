import requests
import json

def query_aws_index():
    url = "http://localhost:9200/_plugins/_sql"
    headers = {"Content-Type": "application/json"}
    data = {"query": "SELECT * FROM aws LIMIT 10"}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        print(json.dumps(result, indent=2))
        return result
    except Exception as e:
        print(f"Error querying aws index: {e}")
        return None

if __name__ == "__main__":
    query_aws_index() 