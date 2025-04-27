from flask import Blueprint, jsonify, request
from werkzeug.utils import secure_filename
import os
import pandas as pd
from typing import Dict, Any

from utils.pattern_analyzer import analyze_patterns
from utils.sample_extractor import extract_samples
from utils.log_processor import process_log_file

# Create blueprint for API routes
api = Blueprint('api', __name__)

# Store uploaded data in memory
uploaded_data = None

ALLOWED_EXTENSIONS = {'csv', 'json'}

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@api.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and initial processing"""
    global uploaded_data
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    try:
        # Create uploads directory if it doesn't exist
        os.makedirs('uploads', exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        file.save(filepath)
        
        # Process the log file
        uploaded_data, results = process_log_file(filepath)
        
        # Clean up the uploaded file
        os.remove(filepath)
        
        return jsonify(results)
    
    except Exception as e:
        print(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api.route('/generate_patterns', methods=['POST'])
def generate_patterns():
    """Generate patterns from the selected column"""
    try:
        if uploaded_data is None:
            return jsonify({'error': 'No data available. Please upload a file first.'}), 400
        
        data = request.get_json()
        column_name = data.get('column')
        
        if not column_name or column_name not in uploaded_data.columns:
            string_columns = uploaded_data.select_dtypes(include=['object']).columns
            if len(string_columns) == 0:
                return jsonify({'error': 'No suitable text columns found in the data.'}), 400
            column_name = string_columns[0]
        
        log_lines = uploaded_data[column_name].tolist()
        patterns = analyze_patterns(log_lines)
        
        result = []
        for sample, pattern in patterns:
            result.append({
                'pattern': pattern,
                'example': sample,
                'count': len([line for line in log_lines 
                            if line and not pd.isna(line) and 
                            analyze_patterns([line])[0][1] == pattern])
            })
        
        result.sort(key=lambda x: x['count'], reverse=True)
        
        return jsonify({
            'patterns': result,
            'column_used': column_name
        })
        
    except Exception as e:
        print(f"Pattern generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api.route('/extract_samples', methods=['POST'])
def extract_pattern_samples():
    """Extract representative samples for each pattern"""
    try:
        if uploaded_data is None:
            return jsonify({'error': 'No data available. Please upload a file first.'}), 400
        
        data = request.get_json()
        column_name = data.get('column')
        
        if not column_name or column_name not in uploaded_data.columns:
            string_columns = uploaded_data.select_dtypes(include=['object']).columns
            if len(string_columns) == 0:
                return jsonify({'error': 'No suitable text columns found in the data.'}), 400
            column_name = string_columns[0]
        
        # Pass the complete DataFrame and column name
        samples = extract_samples(uploaded_data, column_name)
        
        return jsonify({
            'samples': samples,
            'column_used': column_name
        })
        
    except Exception as e:
        print(f"Sample extraction error: {str(e)}")
        return jsonify({'error': str(e)}), 500 