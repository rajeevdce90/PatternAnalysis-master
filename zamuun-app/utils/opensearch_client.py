import json
import logging
import requests
from urllib.parse import urljoin
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OpenSearchClient:
    """Utility class for OpenSearch operations"""
    
    def __init__(self, host='localhost', port=9200, username=None, password=None, use_https=False, use_fallback=False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_https = use_https
        self.use_fallback = use_fallback
        
        # In-memory storage for fallback mode
        self._patterns = []
        
        # Determine protocol
        self.protocol = 'https' if self.use_https else 'http'
        
        # Build base URL
        self.base_url = f'{self.protocol}://{self.host}:{self.port}'
        
        # Set up auth if provided
        self.auth = None
        if self.username and self.password:
            self.auth = (self.username, self.password)
        
        # Check if we're using fallback mode
        if use_fallback:
            logger.info("Using in-memory fallback storage as requested")
    
    def execute_query(self, query, query_language='sql', index_name=None):
        """
        Execute a query against OpenSearch
        
        Args:
            query (str): The query to execute
            query_language (str): The query language - 'sql', 'ppl', or 'dsl'
            index_name (str): The index to target (for DSL queries)
            
        Returns:
            dict: The query results
        """
        try:
            # Choose endpoint based on query language
            if query_language == 'sql':
                endpoint = '_plugins/_sql'
                payload = {'query': query}
            elif query_language == 'ppl':
                endpoint = '_plugins/_ppl'
                payload = {'query': query}
            elif query_language == 'dsl':
                # For DSL, we need to send the query to an index-specific endpoint
                # Parse the DSL query
                if isinstance(query, str):
                    try:
                        dsl_query = json.loads(query)
                    except json.JSONDecodeError as e:
                        # Check if the query is in Dev Tools format (GET index/_search\n{...})
                        dev_tools_match = re.match(r'(?:GET|POST|PUT)\s+([^/\s]+)(?:/_search)?\s*\n(.*)', query, re.DOTALL)
                        if dev_tools_match:
                            # Extract index and query body
                            extracted_index = dev_tools_match.group(1)
                            query_body = dev_tools_match.group(2).strip()
                            try:
                                dsl_query = json.loads(query_body)
                                # Only use extracted index if no index_name was provided
                                if not index_name:
                                    index_name = extracted_index
                                logger.info(f"Converted Dev Tools format query targeting index: {index_name}")
                            except json.JSONDecodeError:
                                return {
                                    'success': False,
                                    'error': f'Invalid DSL query JSON body. Please provide a valid JSON object.'
                                }
                        else:
                            return {
                                'success': False,
                                'error': f'Invalid DSL query format. DSL queries must be valid JSON objects or follow the Dev Tools format (GET index/_search\\n{{...}}). Error: {str(e)}'
                            }
                else:
                    dsl_query = query
                
                # Use provided index_name as priority, then check in the query, otherwise use default
                if not index_name:
                    # Extract index name from query if specified
                    index_name = dsl_query.pop('index', None)
                    
                # If still no index name, use the default
                if not index_name:
                    index_name = '_all'  # Search all indices if no specific index is provided
                
                # Set the endpoint to include the index name
                endpoint = f'{index_name}/_search'
                payload = dsl_query
                
                logger.info(f"DSL query targeting index: {index_name}")
            else:
                return {
                    'success': False,
                    'error': f'Unsupported query language: {query_language}'
                }
            
            # Execute query
            headers = {'Content-Type': 'application/json'}
            api_url = urljoin(self.base_url, endpoint)
            
            logger.info(f"Executing {query_language.upper()} query at {api_url}")
            response = requests.post(api_url, headers=headers, json=payload, auth=self.auth)
            
            if response.status_code == 200:
                result = response.json()
                
                # For DSL, convert the result to match SQL/PPL format
                if query_language == 'dsl':
                    # Extract hits and convert to SQL-like format
                    hits = result.get('hits', {}).get('hits', [])
                    
                    if hits:
                        try:
                            # Extract field names from the first hit
                            first_hit = hits[0]
                            source = first_hit.get('_source', {})
                            
                            # Create schema from fields
                            schema = [{'name': field, 'type': 'text'} for field in source.keys()]
                            
                            # Extract data rows
                            datarows = []
                            for hit in hits:
                                source = hit.get('_source', {})
                                datarows.append(list(source.values()))
                            
                            result = {
                                'schema': schema,
                                'datarows': datarows,
                                'total': result.get('hits', {}).get('total', {}).get('value', 0),
                                'index': index_name  # Include the index name in the result
                            }
                        except Exception as e:
                            logger.error(f"Error formatting DSL response: {str(e)}")
                            # Instead of failing, return the raw result in a basic format
                            field_names = ['_id', '_source']
                            result = {
                                'schema': [{'name': field, 'type': 'text'} for field in field_names],
                                'datarows': [[hit.get('_id', ''), json.dumps(hit.get('_source', {}))] for hit in hits],
                                'total': result.get('hits', {}).get('total', {}).get('value', 0),
                                'index': index_name  # Include the index name in the result
                            }
                    else:
                        # Handle empty result set
                        result = {
                            'schema': [{'name': 'message', 'type': 'text'}],
                            'datarows': [['No results found']],
                            'total': 0,
                            'index': index_name  # Include the index name in the result
                        }
                
                return {
                    'success': True,
                    'data': result,
                    'language': query_language
                }
            else:
                error_message = response.text
                logger.error(f"Query failed: {error_message}")
                return {
                    'success': False,
                    'error': f'Query failed: {error_message}',
                    'language': query_language
                }

        except Exception as e:
            logger.error(f"Error executing query: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
            
    def save_pattern(self, pattern):
        """Save a pattern to OpenSearch or fallback storage"""
        if self.use_fallback:
            # In fallback mode, just store in memory
            self._patterns.append(pattern)
            return {'success': True}
        
        try:
            # In real mode, store in OpenSearch
            endpoint = 'patterns/_doc'
            headers = {'Content-Type': 'application/json'}
            api_url = urljoin(self.base_url, endpoint)
            
            response = requests.post(api_url, headers=headers, json=pattern, auth=self.auth)
            
            if response.status_code in [200, 201]:
                return {'success': True, 'id': response.json().get('_id')}
            else:
                error_message = response.text
                logger.error(f"Failed to save pattern: {error_message}")
                return {'success': False, 'error': error_message}
        except Exception as e:
            logger.error(f"Error saving pattern: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def search_patterns(self, query):
        """Search for patterns in OpenSearch or fallback storage"""
        if self.use_fallback:
            # In fallback mode, search in memory
            results = []
            query_lower = query.lower()
            
            for pattern in self._patterns:
                # Simple string matching
                if query_lower in pattern.get('pattern', '').lower() or \
                   query_lower in pattern.get('example', '').lower():
                    results.append(pattern)
            
            return results
        
        try:
            # In real mode, search in OpenSearch
            endpoint = 'patterns/_search'
            headers = {'Content-Type': 'application/json'}
            api_url = urljoin(self.base_url, endpoint)
            
            # Basic multi-match query
            payload = {
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["pattern", "example", "raw_event"]
                    }
                },
                "size": 100
            }
            
            response = requests.post(api_url, headers=headers, json=payload, auth=self.auth)
            
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                results = [hit.get('_source', {}) for hit in hits]
                return results
            else:
                error_message = response.text
                logger.error(f"Failed to search patterns: {error_message}")
                return []
        except Exception as e:
            logger.error(f"Error searching patterns: {str(e)}")
            return []
    
    def get_all_patterns(self):
        """Get all patterns from OpenSearch or fallback storage"""
        if self.use_fallback:
            # In fallback mode, return all in-memory patterns
            return self._patterns
        
        try:
            # In real mode, get all from OpenSearch
            endpoint = 'patterns/_search'
            headers = {'Content-Type': 'application/json'}
            api_url = urljoin(self.base_url, endpoint)
            
            # Match all query
            payload = {
                "query": {
                    "match_all": {}
                },
                "size": 1000
            }
            
            response = requests.post(api_url, headers=headers, json=payload, auth=self.auth)
            
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                results = [hit.get('_source', {}) for hit in hits]
                return results
            else:
                error_message = response.text
                logger.error(f"Failed to get all patterns: {error_message}")
                return []
        except Exception as e:
            logger.error(f"Error getting all patterns: {str(e)}")
            return [] 