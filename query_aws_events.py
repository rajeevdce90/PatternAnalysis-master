import requests
import json

# OpenSearch connection URL
base_url = 'http://localhost:9200'

print("Querying AWS CloudTrail events...")

def run_query(query_name, query_body):
    print(f"\n--- {query_name} ---")
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{base_url}/aws/_search", 
            data=json.dumps(query_body),
            headers=headers
        )
        
        if response.status_code == 200:
            results = response.json()
            total_hits = results.get('hits', {}).get('total', {}).get('value', 0)
            print(f"Found {total_hits} matches")
            
            for hit in results.get('hits', {}).get('hits', []):
                source = hit.get('_source', {})
                event_time = source.get('eventTime', 'N/A')
                event_name = source.get('eventName', 'N/A')
                event_source = source.get('eventSource', 'N/A')
                user_identity = source.get('userIdentity', {})
                user_type = user_identity.get('type', 'N/A')
                user_name = user_identity.get('userName', user_identity.get('invokedBy', 'N/A'))
                source_ip = source.get('sourceIPAddress', 'N/A')
                
                print(f"Time: {event_time} | Action: {event_name} | Source: {event_source} | User: {user_type}/{user_name} | IP: {source_ip}")
                
                # Print request parameters if available
                if 'requestParameters' in source and source['requestParameters']:
                    print(f"  Request Params: {json.dumps(source['requestParameters'])[:100]}...")
                
                # Print response elements if available
                if 'responseElements' in source and source['responseElements']:
                    print(f"  Response: {json.dumps(source['responseElements'])[:100]}...")
                
                print("---")
        else:
            print(f"Query failed with status code: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"Error executing query: {e}")

# 1. Query all events
all_events_query = {
    "query": {
        "match_all": {}
    },
    "sort": [
        {"eventTime": {"order": "desc"}}
    ],
    "size": 10
}
run_query("All CloudTrail Events (sorted by time)", all_events_query)

# 2. Query events by specific user
user_events_query = {
    "query": {
        "bool": {
            "must": [
                {"match": {"userIdentity.userName": "admin"}}
            ]
        }
    },
    "size": 10
}
run_query("Events by admin user", user_events_query)

# 3. Query events by action type
action_events_query = {
    "query": {
        "bool": {
            "should": [
                {"match": {"eventName": "AssumeRole"}},
                {"match": {"eventName": "ConsoleLogin"}}
            ]
        }
    },
    "size": 10
}
run_query("Authentication-related Events (AssumeRole, ConsoleLogin)", action_events_query)

# 4. Query events by region
region_events_query = {
    "query": {
        "match": {"awsRegion": "us-east-1"}
    },
    "size": 10
}
run_query("Events in us-east-1 region", region_events_query)

print("\nQuery execution completed") 