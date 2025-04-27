from flask import Blueprint, render_template, request, jsonify
from utils.opensearch_client import OpenSearchClient
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create the blueprint
search_bp = Blueprint('search', __name__)

# Initialize OpenSearch client with fallback
opensearch_client = OpenSearchClient(use_fallback=True)

@search_bp.route('/search')
def search():
    """Render the search page (formerly SQL query)"""
    return render_template('search.html')

@search_bp.route('/execute_query', methods=['POST'])
def execute_query():
    """Execute a query against OpenSearch"""
    try:
        # Get request parameters
        query = request.json.get('query')
        query_language = request.json.get('language', 'sql').lower()
        connection_settings = request.json.get('connection', {})
        index_name = request.json.get('index_name')
        tab_id = request.json.get('tab_id', 1)
        
        if not query:
            return jsonify({'error': 'No query provided'}), 400
        
        # Set up OpenSearch client with connection settings
        client = OpenSearchClient(
            host=connection_settings.get('host', 'localhost'),
            port=connection_settings.get('port', 9200),
            username=connection_settings.get('username'),
            password=connection_settings.get('password'),
            use_https=connection_settings.get('useHttps', False),
            use_fallback=connection_settings.get('useFallback', True)
        )
        
        # Execute the query
        result = client.execute_query(query, query_language, index_name)
        
        # Add tab_id to the result
        if result.get('success'):
            result['tab_id'] = tab_id
            
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error executing query: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500 