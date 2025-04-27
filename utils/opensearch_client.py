import os
from opensearchpy import OpenSearch, RequestsHttpConnection
from typing import Dict, List, Optional, Union
import logging
import json

logger = logging.getLogger(__name__)

class OpenSearchClient:
    """Singleton class for managing OpenSearch connection."""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OpenSearchClient, cls).__new__(cls)
            cls._instance.client = None
        return cls._instance
    
    def __init__(self):
        if not self.client:
            self.client = get_client()
    
    def get_client(self) -> OpenSearch:
        """Get the OpenSearch client instance."""
        if not self.client:
            self.client = get_client()
        return self.client
    
    def refresh_client(self) -> None:
        """Refresh the client connection with new settings."""
        self.client = get_client()

# Define path to connections file relative to this script
SETTINGS_DIR = os.path.join(os.path.dirname(__file__), '..', 'settings') # Go up one level from utils
CONNECTIONS_FILE = os.path.join(SETTINGS_DIR, 'connections.json')

def _load_connection_settings_from_file():
    """Loads connection settings from file, returns empty dict if error."""
    if os.path.exists(CONNECTIONS_FILE):
        try:
            with open(CONNECTIONS_FILE, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Error reading or parsing {CONNECTIONS_FILE}: {e}")
            return {}
    return {}

def get_client() -> OpenSearch:
    """Create and return an OpenSearch client instance using saved settings or env vars."""
    # Load settings from file first
    saved_settings = _load_connection_settings_from_file()

    # Use saved setting or fallback to environment variable or default
    host = saved_settings.get('host') or os.getenv('OPENSEARCH_HOST', 'localhost')
    port = saved_settings.get('port') or int(os.getenv('OPENSEARCH_PORT', '9200'))
    use_ssl = saved_settings.get('use_ssl') if saved_settings.get('use_ssl') is not None else (os.getenv('OPENSEARCH_USE_SSL', 'false').lower() == 'true')
    verify_certs = saved_settings.get('verify_certs') if saved_settings.get('verify_certs') is not None else (os.getenv('OPENSEARCH_VERIFY_CERTS', 'false').lower() == 'true')
    username = saved_settings.get('username') or os.getenv('OPENSEARCH_USERNAME') # Allow empty username from file
    password = saved_settings.get('password') or os.getenv('OPENSEARCH_PASSWORD') # Allow empty password from file

    logger.info(f"Initializing OpenSearch client: host={host}, port={port}, use_ssl={use_ssl}, verify_certs={verify_certs}, username={'set' if username else 'not set'}")

    client = OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_auth=(username, password) if username else None,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        connection_class=RequestsHttpConnection
    )
    return client

def list_indices() -> List[Dict]:
    """List all indices with their stats."""
    client = get_client()
    try:
        # Get basic index info
        indices = client.cat.indices(format='json')
        
        # Get detailed stats for each index
        result = []
        for index in indices:
            index_name = index['index']
            stats = client.indices.stats(index=index_name)
            health = client.cluster.health(index=index_name)
            
            result.append({
                'name': index_name,
                'health': health['status'],
                'docs_count': stats['_all']['total']['docs']['count'],
                'size_bytes': stats['_all']['total']['store']['size_in_bytes'],
                'status': index.get('status', 'unknown')
            })
        
        return result
    except Exception as e:
        logger.error(f"Error listing indices: {str(e)}")
        raise

def get_index_info(index_name: str) -> Dict:
    """Get detailed information about a specific index."""
    client = get_client()
    try:
        settings = client.indices.get_settings(index=index_name)
        mappings = client.indices.get_mapping(index=index_name)
        stats = client.indices.stats(index=index_name)
        health = client.cluster.health(index=index_name)
        
        return {
            'name': index_name,
            'settings': settings[index_name]['settings'],
            'mappings': mappings[index_name]['mappings'],
            'stats': stats['indices'][index_name],
            'health': health
        }
    except Exception as e:
        logger.error(f"Error getting index info for {index_name}: {str(e)}")
        raise

def create_index(index_name: str, settings: Optional[Dict] = None, mappings: Optional[Dict] = None) -> Dict:
    """Create a new index with optional settings and mappings."""
    client = get_client()
    try:
        body = {}
        if settings:
            body['settings'] = settings
        if mappings:
            body['mappings'] = mappings
            
        response = client.indices.create(index=index_name, body=body)
        return response
    except Exception as e:
        logger.error(f"Error creating index {index_name}: {str(e)}")
        raise

def update_index(index_name: str, settings: Optional[Dict] = None, mappings: Optional[Dict] = None) -> Dict:
    """Update an existing index's settings or mappings."""
    client = get_client()
    try:
        responses = {}
        
        if settings:
            responses['settings'] = client.indices.put_settings(
                index=index_name,
                body=settings
            )
            
        if mappings:
            responses['mappings'] = client.indices.put_mapping(
                index=index_name,
                body=mappings
            )
            
        return responses
    except Exception as e:
        logger.error(f"Error updating index {index_name}: {str(e)}")
        raise

def delete_index(index_name: str) -> Dict:
    """Delete an index."""
    client = get_client()
    try:
        response = client.indices.delete(index=index_name)
        return response
    except Exception as e:
        logger.error(f"Error deleting index {index_name}: {str(e)}")
        raise

def reindex(source_index: str, target_index: str, query: Optional[Dict] = None) -> str:
    """Reindex data from source to target index, returning task ID."""
    client = get_client()
    try:
        body = {
            'source': {
                'index': source_index
            },
            'dest': {
                'index': target_index
            }
        }
        
        if query:
            body['source']['query'] = query
            
        # Start reindex asynchronously and get task ID
        response = client.reindex(body=body, request_timeout=3600, wait_for_completion=False)
        return response['task'] # Return the task ID
    except Exception as e:
        logger.error(f"Error starting reindex from {source_index} to {target_index}: {str(e)}")
        raise

def bulk_index(index_name: str, documents: List[Dict]) -> Dict:
    """Bulk index multiple documents."""
    client = get_client()
    try:
        operations = []
        for doc in documents:
            operations.extend([
                {'index': {'_index': index_name}},
                doc
            ])
            
        response = client.bulk(operations)
        return response
    except Exception as e:
        logger.error(f"Error bulk indexing to {index_name}: {str(e)}")
        raise 