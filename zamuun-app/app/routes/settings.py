import os
import json
import time
from flask import Blueprint, render_template, request, jsonify, current_app
from opensearchpy import OpenSearch, RequestsHttpConnection

# Create the blueprint
settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings')
def settings_page():
    """Render the settings page"""
    return render_template('settings.html')

@settings_bp.route('/get_settings', methods=['GET'])
def get_settings():
    """Retrieve current application settings"""
    settings_file = current_app.config['SETTINGS_FILE']
    
    # Default settings
    default_settings = {
        'connection': {
            'host': current_app.config['OPENSEARCH_HOST'],
            'port': current_app.config['OPENSEARCH_PORT'],
            'username': current_app.config['OPENSEARCH_USERNAME'],
            'password': current_app.config['OPENSEARCH_PASSWORD'],
            'use_https': current_app.config['OPENSEARCH_USE_HTTPS']
        },
        'display': {
            'default_rows_per_page': 100,
            'max_columns_preview': 50,
            'theme': 'light',
            'default_visualization': 'table'
        },
        'advanced': {
            'query_timeout': 60,
            'auto_refresh': False,
            'refresh_interval': 60,
            'default_index': current_app.config['DEFAULT_INDEX']
        }
    }
    
    # If settings file exists, load from it
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r') as f:
                saved_settings = json.load(f)
                # Merge with default settings for any missing keys
                for category in default_settings:
                    if category in saved_settings:
                        for key in default_settings[category]:
                            if key not in saved_settings[category]:
                                saved_settings[category][key] = default_settings[category][key]
                    else:
                        saved_settings[category] = default_settings[category]
                return jsonify(saved_settings)
        except Exception as e:
            return jsonify({"error": str(e), "settings": default_settings})
    
    # If no settings file, return defaults
    return jsonify(default_settings)

@settings_bp.route('/save_settings', methods=['POST'])
def save_settings():
    """Save application settings"""
    settings_file = current_app.config['SETTINGS_FILE']
    
    try:
        settings = request.get_json()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)
        
        # Save settings to file
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        return jsonify({"success": True, "message": "Settings saved successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@settings_bp.route('/test_connection', methods=['POST'])
def test_connection():
    """Test OpenSearch connection settings"""
    try:
        # Get connection settings from request
        conn_settings = request.get_json()
        
        # Create OpenSearch client with provided settings
        client = OpenSearch(
            hosts=[{
                'host': conn_settings.get('host', 'localhost'),
                'port': int(conn_settings.get('port', 9200))
            }],
            http_auth=(
                conn_settings.get('username', ''), 
                conn_settings.get('password', '')
            ) if conn_settings.get('username') else None,
            use_ssl=conn_settings.get('use_https', False),
            verify_certs=False,
            connection_class=RequestsHttpConnection,
            timeout=10
        )
        
        # Test connection with a simple query
        start_time = time.time()
        response = client.info()
        response_time = time.time() - start_time
        
        return jsonify({
            "success": True,
            "message": "Connection successful",
            "response_time": f"{response_time:.2f}s",
            "version": response.get('version', {}).get('number', 'Unknown')
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Connection failed",
            "error": str(e)
        }) 