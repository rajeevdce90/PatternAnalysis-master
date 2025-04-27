from flask import Blueprint, render_template, request, jsonify
from config.config import Config
import os
import json
from datetime import datetime
import uuid
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create the blueprint
saved_queries_bp = Blueprint('saved_queries', __name__)

@saved_queries_bp.route('/saved_queries')
def saved_queries():
    """Render the saved queries page"""
    return render_template('saved_queries.html')

@saved_queries_bp.route('/save_query', methods=['POST'])
def save_query():
    """Save a query to the saved queries directory"""
    try:
        query_data = request.json
        
        # Validate required fields
        if not query_data.get('name') or not query_data.get('sql'):
            return jsonify({'success': False, 'error': 'Name and SQL query are required'})
        
        # Add unique ID and ensure created timestamp exists
        if not query_data.get('id'):
            query_data['id'] = str(uuid.uuid4())
        
        if not query_data.get('created'):
            query_data['created'] = datetime.now().isoformat()
        
        # Save to file
        filename = os.path.join(Config.SAVED_QUERIES_DIR, f"{query_data['id']}.json")
        with open(filename, 'w') as f:
            json.dump(query_data, f, indent=2)
        
        return jsonify({'success': True, 'id': query_data['id']})
    
    except Exception as e:
        logger.error(f"Error saving query: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@saved_queries_bp.route('/get_saved_queries')
def get_saved_queries():
    """Get all saved queries"""
    try:
        queries = []
        
        # Load all query files
        for filename in os.listdir(Config.SAVED_QUERIES_DIR):
            if filename.endswith('.json'):
                file_path = os.path.join(Config.SAVED_QUERIES_DIR, filename)
                with open(file_path, 'r') as f:
                    query = json.load(f)
                    queries.append(query)
        
        # Sort by most recent first
        queries.sort(key=lambda x: x.get('created', ''), reverse=True)
        
        return jsonify({'success': True, 'queries': queries})
    
    except Exception as e:
        logger.error(f"Error retrieving queries: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@saved_queries_bp.route('/delete_query/<query_id>', methods=['DELETE'])
def delete_query(query_id):
    """Delete a saved query"""
    try:
        filename = os.path.join(Config.SAVED_QUERIES_DIR, f"{query_id}.json")
        
        if not os.path.exists(filename):
            return jsonify({'success': False, 'error': 'Query not found'})
        
        os.remove(filename)
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error deleting query: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}) 