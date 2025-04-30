from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required
from werkzeug.utils import secure_filename
import os
from app.services.data_ingestion import DataIngestionService
from app.services.opensearch_service import OpenSearchService

bp = Blueprint('data', __name__, url_prefix='/api/data')
data_service = DataIngestionService()
opensearch = OpenSearchService()

@bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload and data ingestion."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    target_index = request.form.get('target_index')
    if not target_index:
        return jsonify({'success': False, 'message': 'Target index is required'}), 400

    datatype = request.form.get('datatype')
    if not datatype:
        return jsonify({'success': False, 'message': 'Data type is required'}), 400

    try:
        # Save file
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Process file
        result = data_service.process_file_upload(file_path, target_index, datatype)

        # Clean up
        os.remove(file_path)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error processing file: {str(e)}'
        }), 500

@bp.route('/collectors/rest', methods=['POST'])
@login_required
def start_rest_collector():
    """Start a REST API collector."""
    data = request.get_json()
    
    required_fields = ['url', 'method', 'interval', 'target_index', 'datatype']
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return jsonify({
            'success': False,
            'message': f'Missing required fields: {", ".join(missing_fields)}'
        }), 400

    result = data_service.start_rest_collector(data)
    return jsonify(result)

@bp.route('/collectors/<collector_id>', methods=['DELETE'])
@login_required
def stop_collector(collector_id):
    """Stop a running collector."""
    result = data_service.stop_collector(collector_id)
    return jsonify(result)

@bp.route('/collectors', methods=['GET'])
@login_required
def get_collectors():
    """Get all active collectors."""
    collectors = data_service.get_active_collectors()
    return jsonify({
        'success': True,
        'collectors': collectors
    })

@bp.route('/listeners/syslog', methods=['POST'])
@login_required
def start_syslog_listener():
    """Start a Syslog listener."""
    data = request.get_json()
    
    required_fields = ['port', 'target_index', 'datatype']
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return jsonify({
            'success': False,
            'message': f'Missing required fields: {", ".join(missing_fields)}'
        }), 400

    result = data_service.start_syslog_listener(data)
    return jsonify(result)

@bp.route('/listeners/<listener_id>', methods=['DELETE'])
@login_required
def stop_listener(listener_id):
    """Stop a running listener."""
    result = data_service.stop_listener(listener_id)
    return jsonify(result)

@bp.route('/listeners', methods=['GET'])
@login_required
def get_listeners():
    """Get all active listeners."""
    listeners = data_service.get_active_listeners()
    return jsonify({
        'success': True,
        'listeners': listeners
    })

@bp.route('/indices', methods=['GET'])
@login_required
def get_indices():
    """Get all indices and their statistics."""
    try:
        stats = opensearch.get_index_stats()
        indices = []
        
        for index_name, stats in stats['indices'].items():
            index_info = {
                'name': index_name,
                'doc_count': stats['total']['docs']['count'],
                'size_bytes': stats['total']['store']['size_in_bytes'],
                'settings': opensearch.get_index_settings(index_name),
                'mapping': opensearch.get_index_mapping(index_name)
            }
            indices.append(index_info)

        return jsonify({
            'success': True,
            'indices': indices
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error retrieving indices: {str(e)}'
        }), 500

@bp.route('/indices', methods=['POST'])
@login_required
def create_index():
    """Create a new index."""
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({
            'success': False,
            'message': 'Index name is required'
        }), 400

    try:
        result = opensearch.create_index(
            data['name'],
            settings=data.get('settings'),
            mappings=data.get('mappings')
        )
        return jsonify({
            'success': True,
            'message': f'Index {data["name"]} created successfully',
            'result': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error creating index: {str(e)}'
        }), 500

@bp.route('/indices/<index_name>', methods=['DELETE'])
@login_required
def delete_index(index_name):
    """Delete an index."""
    try:
        result = opensearch.delete_index(index_name)
        return jsonify({
            'success': True,
            'message': f'Index {index_name} deleted successfully',
            'result': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error deleting index: {str(e)}'
        }), 500 