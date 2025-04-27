from flask import Blueprint, render_template, request, jsonify
import os
import pandas as pd
from config.config import Config
from utils.opensearch_client import OpenSearchClient
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create the blueprint
main_bp = Blueprint('main', __name__)

# Initialize OpenSearch client with fallback
opensearch_client = OpenSearchClient(use_fallback=True)

@main_bp.route('/')
def index():
    """Render the home page"""
    return render_template('index.html')

@main_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload for pattern analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        # Save the file
        file_path = os.path.join(Config.UPLOAD_FOLDER, 'temp_data.csv')
        file.save(file_path)
        
        # Read the file
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file.filename.endswith('.json'):
            df = pd.read_json(file_path)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
            
        # Get column information
        columns = [{'name': col, 'type': str(df[col].dtype)} for col in df.columns]
        
        # Convert first 1000 rows to list of dictionaries for events
        events = df.head(1000).replace({pd.NaT: None}).to_dict('records')
        
        return jsonify({
            'success': True,
            'columns': columns,
            'events': events,
            'total_events': len(df),
            'valid_events': df.notna().all(axis=1).sum()
        })
        
    except Exception as e:
        logger.error(f"Error in upload_file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@main_bp.route('/generate_patterns', methods=['POST'])
def generate_patterns():
    """Generate patterns from uploaded file"""
    try:
        data = request.json
        column = data.get('column')
        
        if not column:
            return jsonify({'error': 'No column specified'}), 400
            
        # Read the temporary file
        file_path = os.path.join(Config.UPLOAD_FOLDER, 'temp_data.csv')
        df = pd.read_csv(file_path)
        
        # Get unique patterns from the specified column
        patterns = df[column].unique().tolist()
        
        # Create pattern objects with examples
        pattern_objects = []
        for pattern in patterns:
            example = df[df[column] == pattern].iloc[0][column]
            pattern_obj = {
                'pattern': pattern,
                'example': example,
                'raw_event': example
            }
            # Save to OpenSearch
            opensearch_client.save_pattern(pattern_obj)
            pattern_objects.append(pattern_obj)
        
        return jsonify({
            'success': True,
            'patterns': pattern_objects
        })
        
    except Exception as e:
        logger.error(f"Error in generate_patterns: {str(e)}")
        return jsonify({'error': str(e)}), 500

@main_bp.route('/search_patterns', methods=['POST'])
def search_patterns():
    """Search for patterns in OpenSearch"""
    try:
        data = request.json
        query = data.get('query', '')
        
        if not query:
            # If no query, return all patterns
            results = opensearch_client.get_all_patterns()
        else:
            # Search patterns
            results = opensearch_client.search_patterns(query)
        
        return jsonify({
            'success': True,
            'results': results,
            'using_fallback': opensearch_client.use_fallback
        })
        
    except Exception as e:
        logger.error(f"Error in search_patterns: {str(e)}")
        return jsonify({'error': str(e)}), 500 