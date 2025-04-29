from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from routes import api
import os
import pandas as pd
from utils.data_obscurer import DataObscurer
from utils.regex_parser import RegexParser
import json
import logging
from utils.opensearch_client import (
    OpenSearchClient,
    get_client,
    list_indices,
    create_index,
    get_index_info,
    delete_index,
    reindex,
    bulk_index
)
import requests
from urllib.parse import urljoin
import uuid
from datetime import datetime, timedelta
import re
from functools import wraps
import io
import qrcode
from base64 import b64encode
from utils.email_sender import email_sender
from utils.alert_checker import alert_checker
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Import User and Role directly from the models.py file
# This avoids the circular import issue
import importlib.util
spec = importlib.util.spec_from_file_location("models_module", "./models.py")
models_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(models_module)
User = models_module.User
Role = models_module.Role

# Initialize OpenSearch client
opensearch_client = OpenSearchClient()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
logger.info(f"Upload directory: {app.config['UPLOAD_FOLDER']}")

# Register blueprints
app.register_blueprint(api)

# Initialize regex parser
regex_parser = RegexParser()

# Import Alert after app initialization to avoid circular dependencies
from models.alert import Alert

# Temporarily disable alert checker to test stability
# alert_checker.start()

# Directory for saved queries
SAVED_QUERIES_DIR = 'saved_queries'

# Directory for settings
SETTINGS_DIR = 'settings'
TAGS_FILE = os.path.join(SETTINGS_DIR, 'tags.json')
SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'app_settings.json')
CONNECTIONS_FILE = os.path.join(SETTINGS_DIR, 'connections.json')

# Ensure directories exist
if not os.path.exists(SAVED_QUERIES_DIR):
    os.makedirs(SAVED_QUERIES_DIR)

if not os.path.exists(SETTINGS_DIR):
    os.makedirs(SETTINGS_DIR)

# Check if admin user exists, create if not
def ensure_admin_user_exists():
    users = User.get_all_users()
    if not users:
        admin_role = Role.get_role_by_name('Administrator')
        if not admin_role:
            # Create roles first
            roles = Role.get_all_roles()
            for role in roles:
                if role.name == 'Administrator':
                    admin_role = role
                    break
        
        if admin_role:
            User.create_user(
                username='admin',
                email='admin@example.com',
                password='admin123',  # Default password, should be changed
                role_id=admin_role.id
            )
            logger.info("Created default admin user")

ensure_admin_user_exists()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin access decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        
        user = User.get_user_by_id(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        role = user.get_role()
        if not role or role.name != 'Administrator':
            flash('Admin access required for this page')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function

# Tag access check function
def check_tag_access(tag_id):
    if 'user_id' not in session:
        return False
    
    user = User.get_user_by_id(session['user_id'])
    if not user:
        return False
    
    role = user.get_role()
    if not role:
        return False
    
    # Admins have access to everything
    if role.name == 'Administrator':
        return True
    
    # Check tag access for other roles
    return role.has_access_to_tag(tag_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_user_by_username(username)
        if user and user.check_password(password):
            # Check if this is a temporary password that needs to be changed
            if user.is_temp_password:
                # Generate a reset token and redirect to reset password page
                reset_token = user.generate_password_reset_token(expiry_hours=1)
                User.update_user(user.id, reset_token=reset_token, reset_token_expiry=user.reset_token_expiry)
                return redirect(url_for('reset_password', token=reset_token))
            
            # If 2FA is enabled, redirect to OTP verification
            if user.otp_enabled:
                # Store user_id in session temporarily for OTP verification
                session['temp_user_id'] = user.id
                return redirect(url_for('verify_otp'))
            else:
                # No 2FA, proceed with normal login
                session['user_id'] = user.id
                session['username'] = user.username
                
                # Check if user is admin
                role = user.get_role()
                session['is_admin'] = role and role.name == 'Administrator'
                
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('index'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # Check if we have a temporary user ID from login
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        
        user = User.get_user_by_id(session['temp_user_id'])
        if not user:
            session.pop('temp_user_id', None)
            return redirect(url_for('login'))
        
        if user.verify_otp(otp_code):
            # OTP verification successful, complete login
            session.pop('temp_user_id', None)
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Check if user is admin
            role = user.get_role()
            session['is_admin'] = role and role.name == 'Administrator'
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code')
    
    return render_template('verify_otp.html')

@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        
        # If 2FA is already enabled, this is a disable request
        if user.otp_enabled:
            if user.verify_otp(otp_code):
                user.otp_enabled = False
                user.otp_secret = None
                User.update_user(user.id, otp_enabled=False, otp_secret=None)
                flash('Two-factor authentication disabled successfully')
                return redirect(url_for('profile'))
            else:
                flash('Invalid verification code')
        else:
            # This is an enable request
            if user.verify_otp(otp_code):
                user.otp_enabled = True
                User.update_user(user.id, otp_enabled=True, otp_secret=user.otp_secret)
                flash('Two-factor authentication enabled successfully')
                return redirect(url_for('profile'))
            else:
                flash('Invalid verification code')
    
    # Generate a new secret if not already enabled
    if not user.otp_enabled:
        user.generate_otp_secret()
    
    # Generate QR code
    qr_uri = user.get_otp_uri()
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered)
    qr_code_base64 = b64encode(buffered.getvalue()).decode('utf-8')
    
    return render_template('setup_2fa.html', 
                           user=user,
                           qr_code=qr_code_base64,
                           secret=user.otp_secret)

@app.route('/api/user/2fa/status', methods=['GET'])
@login_required
def get_2fa_status():
    user = User.get_user_by_id(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'enabled': user.otp_enabled
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/user_management')
@admin_required
def user_management():
    users = User.get_all_users()
    roles = Role.get_all_roles()
    return render_template('user_management.html', users=users, roles=roles)

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    users = User.get_all_users()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role_id': user.role_id,
        'created_at': user.created_at,
        'is_active': user.is_active
    } for user in users])

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role_id = data.get('role_id')
    
    if not all([username, email, password, role_id]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Validate role exists
    role = Role.get_role_by_id(role_id)
    if not role:
        return jsonify({'error': 'Invalid role ID'}), 400
    
    user = User.create_user(username, email, password, role_id)
    if not user:
        return jsonify({'error': 'User already exists with that username or email'}), 400
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role_id': user.role_id,
        'created_at': user.created_at,
        'is_active': user.is_active
    }), 201

@app.route('/api/users/<user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    data = request.json
    updates = {}
    
    if 'username' in data:
        updates['username'] = data['username']
    if 'email' in data:
        updates['email'] = data['email']
    if 'password' in data:
        updates['password'] = data['password']
    if 'role_id' in data:
        updates['role_id'] = data['role_id']
    if 'is_active' in data:
        updates['is_active'] = data['is_active']
    
    if not updates:
        return jsonify({'error': 'No updates provided'}), 400
    
    success = User.update_user(user_id, **updates)
    if not success:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'success': True})

@app.route('/api/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    # Don't allow deleting yourself
    if session.get('user_id') == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    success = User.delete_user(user_id)
    return jsonify({'success': success})

@app.route('/api/roles', methods=['GET'])
@admin_required
def get_roles():
    roles = Role.get_all_roles()
    return jsonify([role.to_dict() for role in roles])

@app.route('/api/roles', methods=['POST'])
@admin_required
def create_role():
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    tag_access = data.get('tag_access', [])
    
    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    
    role = Role.create_role(name, description, tag_access)
    if not role:
        return jsonify({'error': 'Role with this name already exists'}), 400
    
    return jsonify(role.to_dict()), 201

@app.route('/api/roles/<role_id>', methods=['GET'])
@admin_required
def get_role(role_id):
    role = Role.get_role_by_id(role_id)
    if not role:
        return jsonify({'error': 'Role not found'}), 404
    
    return jsonify(role.to_dict())

@app.route('/api/roles/<role_id>', methods=['PUT'])
@admin_required
def update_role(role_id):
    data = request.json
    updates = {}
    
    if 'name' in data:
        updates['name'] = data['name']
    if 'description' in data:
        updates['description'] = data['description']
    if 'tag_access' in data:
        updates['tag_access'] = data['tag_access']
    
    if not updates:
        return jsonify({'error': 'No updates provided'}), 400
    
    success = Role.update_role(role_id, **updates)
    if not success:
        return jsonify({'error': 'Role not found'}), 404
    
    return jsonify({'success': True})

@app.route('/api/roles/<role_id>', methods=['DELETE'])
@admin_required
def delete_role(role_id):
    success = Role.delete_role(role_id)
    if not success:
        return jsonify({'error': 'Cannot delete role that is assigned to users'}), 400
    
    return jsonify({'success': True})

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match')
            return redirect(url_for('change_password'))
        
        user = User.get_user_by_id(session['user_id'])
        if not user or not user.check_password(current_password):
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))
        
        User.update_user(user.id, password=new_password)
        flash('Password updated successfully')
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    if request.method == 'POST':
        new_email = request.form.get('email')
        
        if not new_email:
            flash('Email is required')
            return redirect(url_for('profile'))
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, new_email):
            flash('Invalid email format')
            return redirect(url_for('profile'))
        
        # Check if email is already in use by another user
        existing_user = User.get_user_by_email(new_email)
        if existing_user and existing_user.id != session['user_id']:
            flash('Email is already in use by another account')
            return redirect(url_for('profile'))
        
        # Update the user's email
        success = User.update_user(session['user_id'], email=new_email)
        if success:
            flash('Email updated successfully')
        else:
            flash('Failed to update email')
        
        return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    user = User.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    role = user.get_role()
    role_name = role.name if role else 'No Role'
    
    return render_template('profile.html', user=user, role_name=role_name)

@app.route('/')
@login_required
def index():
    # Redirect root to the SQL Query page
    return redirect(url_for('sql_query'))

@app.route('/add_data')
@login_required
def add_data():
    # Render the template previously used for home
    return render_template('index.html')

@app.route('/search')
@login_required
def search():
    return render_template('search.html') # opensearch_available=not opensearch_client.use_fallback) - Need to re-check client status

@app.route('/search_data', methods=['POST'])
@login_required
def search_data():
    try:
        data = request.get_json()
        query = data.get('query', '')
        
        if not query:
            return jsonify({'error': 'Query is required'}), 400

        # Search in OpenSearch or fallback storage
        results = opensearch_client.search(query)
        
        return jsonify({
            'results': results,
            'using_fallback': opensearch_client.use_fallback
        })
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        # Get target index
        target_index = request.form.get('index')
        if not target_index:
            return jsonify({'error': 'Target index is required'}), 400
            
        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_data.csv')
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
        
        # Store target index in session for later use
        session['target_index'] = target_index
        
        return jsonify({
            'success': True,
            'columns': columns,
            'events': events,
            'total_events': len(df),
            'valid_events': df.notna().all(axis=1).sum(),
            'target_index': target_index
        })
        
    except Exception as e:
        logger.error(f"Error in upload_file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/generate_patterns', methods=['POST'])
def generate_patterns():
    try:
        data = request.json
        column = data.get('column')
        
        if not column:
            return jsonify({'error': 'No column specified'}), 400
            
        # Read the temporary file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_data.csv')
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

@app.route('/search_patterns', methods=['POST'])
def search_patterns():
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

@app.route('/generate_regex', methods=['POST'])
def generate_regex():
    try:
        logger.debug("Generate regex request received")
        data = request.json
        patterns = data.get('patterns', [])
        
        if not patterns:
            return jsonify({
                'success': False,
                'error': 'No patterns provided'
            }), 400
            
        # Clear existing patterns
        regex_parser.clear_patterns()
        
        # Add each pattern
        for pattern in patterns:
            regex_parser.add_pattern(
                pattern.get('pattern', ''),
                pattern.get('example', '')
            )
            
        # Get all patterns with their regex equivalents
        regex_patterns = regex_parser.get_patterns()
        
        return jsonify({
            'success': True,
            'patterns': regex_patterns
        })
        
    except Exception as e:
        logger.error(f"Error in generate_regex: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/parse_log', methods=['POST'])
def parse_log():
    try:
        logger.debug("Parse log request received")
        data = request.json
        log_line = data.get('log_line', '')
        
        if not log_line:
            return jsonify({
                'success': False,
                'error': 'No log line provided'
            }), 400
            
        # Parse the log line
        result = regex_parser.parse_log(log_line)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error in parse_log: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/obscure_data', methods=['POST'])
def obscure_data():
    try:
        logger.debug("Obscure data request received")
        # Get the original data
        temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_data.csv')
        logger.debug(f"Looking for file at: {temp_file_path}")
        
        if not os.path.exists(temp_file_path):
            logger.error(f"File not found at: {temp_file_path}")
            return jsonify({
                'success': False,
                'error': 'No data file found. Please upload a file first.'
            }), 400
            
        # Read the data
        logger.debug("Reading data file")
        df = pd.read_csv(temp_file_path)
        logger.debug(f"Data read successfully, shape: {df.shape}")
        
        # Get the patterns from the previous analysis
        patterns = request.json.get('patterns', [])
        logger.debug(f"Received patterns: {patterns}")
        
        # Create DataObscurer instance and process the data
        obscurer = DataObscurer()
        result = obscurer.process_data(df, patterns)
        
        if not result['success']:
            logger.error(f"Data obscuration failed: {result.get('error')}")
            return jsonify(result), 500
            
        logger.debug("Data obscuration successful")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in obscure_data: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/sql_query')
@login_required
def sql_query():
    return render_template('sql_query.html')

@app.route('/execute_sql', methods=['POST'])
@login_required
def execute_sql():
    try:
        data = request.json
        sql_query = data.get('query')
        query_language = data.get('language', 'sql')
        connection = data.get('connection', {})
        index_name = data.get('index_name')

        if not sql_query:
            return jsonify({'error': 'No query provided'}), 400

        # Get connection settings
        host = connection.get('host', 'localhost')
        port = connection.get('port', '9200')
        use_https = connection.get('useHttps', False)
        protocol = 'https' if use_https else 'http'
        
        # Build base URL
        base_url = f"{protocol}://{host}:{port}"
        
        # Set up authentication if provided
        auth = None
        if connection.get('useAuth'):
            auth = (connection.get('username'), connection.get('password'))

        # Choose endpoint based on query language
        if query_language == 'sql':
            endpoint = '_plugins/_sql'
            payload = {'query': sql_query}
        elif query_language == 'ppl':
            endpoint = '_plugins/_ppl'
            payload = {'query': sql_query}
        elif query_language == 'dsl':
            if not index_name:
                return jsonify({'error': 'Index name is required for DSL queries'}), 400
            endpoint = f'{index_name}/_search'
            try:
                payload = json.loads(sql_query)
            except json.JSONDecodeError:
                return jsonify({'error': 'Invalid DSL query format. Must be valid JSON'}), 400
        else:
            return jsonify({'error': 'Unsupported query language'}), 400

        # Execute query
        headers = {'Content-Type': 'application/json'}
        url = urljoin(base_url, endpoint)
        
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            auth=auth,
            verify=False if use_https else None  # Skip SSL verification if using HTTPS
        )
        
        if response.status_code == 200:
            result = response.json()
            return jsonify({
                'success': True,
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Query failed: {response.text}'
            }), response.status_code
        
    except Exception as e:
        logger.error(f"Error executing query: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/save_query', methods=['POST'])
@login_required
def save_query():
    try:
        data = request.json
        query_text = data.get('query', '')
        query_name = data.get('name', 'Unnamed Query')
        query_description = data.get('description', '')
        save_type = data.get('type', 'query')
        
        if not query_text:
            return jsonify({'error': 'Query text is required'}), 400
        
        # Generate a unique ID for the query
        query_id = str(uuid.uuid4())
        
        # Create base query object
        query_obj = {
            'id': query_id,
            'name': query_name,
            'description': query_description,
            'query': query_text,
            'type': save_type,
            'created_at': datetime.now().isoformat(),
            'created_by': session.get('user_id', 'unknown'),
            'created_by_username': session.get('username', 'unknown')
        }
        
        # Add type-specific data
        if save_type == 'alert':
            # Create an alert
            alert = Alert.create_alert(
                name=query_name,
                query_id=query_id,
                threshold=data.get('threshold'),
                condition=data.get('condition', 'greater_than'),
                frequency=int(data.get('frequency', 15)),
                timespan=60,  # Default to 1 hour
                created_by=session.get('user_id'),
                description=query_description
            )
            query_obj['alert_id'] = alert.id
            
        elif save_type == 'report':
            # Add report-specific fields
            query_obj['report_schedule'] = data.get('schedule', 'daily')
            query_obj['report_format'] = data.get('format', 'pdf')
            query_obj['last_run'] = None
            query_obj['next_run'] = None
            
        elif save_type == 'dashboard':
            # Add dashboard-specific fields
            query_obj['dashboard_layout'] = data.get('layout', 'full')
            query_obj['refresh_interval'] = int(data.get('refreshInterval', 5))
            query_obj['default_visualization'] = data.get('defaultVisualization', 'table')
        
        # Save to file
        query_file = os.path.join(SAVED_QUERIES_DIR, f"{query_id}.json")
        with open(query_file, 'w') as f:
            json.dump(query_obj, f, indent=2)
        
        return jsonify({
            'success': True,
            'query_id': query_id,
            'type': save_type
        })
        
    except Exception as e:
        logger.error(f"Error in save_query: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_saved_queries')
@login_required
def get_saved_queries():
    try:
        queries = []
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        role = user.get_role() if user else None
        
        is_admin = role and role.name == 'Administrator'
        
        for filename in os.listdir(SAVED_QUERIES_DIR):
            if filename.endswith('.json'):
                with open(os.path.join(SAVED_QUERIES_DIR, filename), 'r') as f:
                    query_data = json.load(f)
                    
                    # Filter queries based on tag access
                    if is_admin or not query_data.get('tags'):
                        # Admin can see all queries, or queries without tags are visible to all
                        queries.append(query_data)
                    else:
                        # Check if user has access to any of the query's tags
                        has_access = False
                        for tag in query_data.get('tags', []):
                            if role and tag in role.tag_access:
                                has_access = True
                                break
                        
                        # If created by the current user, always include
                        if query_data.get('created_by') == user_id:
                            has_access = True
                            
                        if has_access:
                            queries.append(query_data)
        
        # Sort by creation date (newest first)
        queries.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify(queries)
        
    except Exception as e:
        logger.error(f"Error in get_saved_queries: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/get_tags')
@login_required
def get_tags():
    try:
        if os.path.exists(TAGS_FILE):
            with open(TAGS_FILE, 'r') as f:
                tags = json.load(f)
        else:
            # Create default tags if the file doesn't exist
            tags = [
                {
                    "id": str(uuid.uuid4()),
                    "name": "Analytics",
                    "color": "#0d6efd",
                    "description": "Queries for analytics and reporting"
                },
                {
                    "id": str(uuid.uuid4()),
                    "name": "Dashboard",
                    "color": "#6c757d",
                    "description": "Queries used in dashboards"
                },
                {
                    "id": str(uuid.uuid4()),
                    "name": "Investigation",
                    "color": "#dc3545",
                    "description": "Queries for investigative purposes"
                },
                {
                    "id": str(uuid.uuid4()),
                    "name": "Template",
                    "color": "#198754",
                    "description": "Template queries for reuse"
                }
            ]
            with open(TAGS_FILE, 'w') as f:
                json.dump(tags, f, indent=2)
                
        # Filter tags based on user permissions
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        role = user.get_role() if user else None
        
        if role and role.name == 'Administrator':
            # Admin can see all tags
            return jsonify(tags)
        
        # Filter tags based on user's role access
        accessible_tags = []
        for tag in tags:
            if not role or tag['id'] in role.tag_access:
                accessible_tags.append(tag)
        
        return jsonify(accessible_tags)
        
    except Exception as e:
        logger.error(f"Error in get_tags: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/add_tag', methods=['POST'])
@admin_required
def add_tag():
    try:
        tag_data = request.json
        
        # Validate required fields
        if not tag_data.get('name'):
            return jsonify({'error': 'Tag name is required'}), 400
        
        # Load existing tags
        tags = []
        if os.path.exists(TAGS_FILE):
            with open(TAGS_FILE, 'r') as f:
                tags = json.load(f)
        
        # Check if tag with same name already exists
        if any(tag['name'].lower() == tag_data['name'].lower() for tag in tags):
            return jsonify({'error': 'A tag with this name already exists'}), 400
        
        # Add ID to new tag
        tag_data['id'] = str(uuid.uuid4())
        
        # Add tag to list
        tags.append(tag_data)
        
        # Save tags
        with open(TAGS_FILE, 'w') as f:
            json.dump(tags, f, indent=2)
            
        return jsonify({'success': True, 'id': tag_data['id']})
    except Exception as e:
        logger.error(f"Error adding tag: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/update_tag', methods=['PUT'])
@admin_required
def update_tag():
    try:
        tag_data = request.json
        
        # Validate required fields
        if not tag_data.get('id') or not tag_data.get('name'):
            return jsonify({'error': 'Tag ID and name are required'}), 400
        
        # Load existing tags
        if not os.path.exists(TAGS_FILE):
            return jsonify({'error': 'No tags found'}), 404
            
        with open(TAGS_FILE, 'r') as f:
            tags = json.load(f)
        
        # Find the tag to update
        tag_index = -1
        for i, tag in enumerate(tags):
            if tag['id'] == tag_data['id']:
                tag_index = i
                break
        
        if tag_index == -1:
            return jsonify({'error': 'Tag not found'}), 404
        
        # Check if new name conflicts with another tag
        for i, tag in enumerate(tags):
            if i != tag_index and tag['name'].lower() == tag_data['name'].lower():
                return jsonify({'error': 'A tag with this name already exists'}), 400
        
        # Update tag
        tags[tag_index] = tag_data
        
        # Save tags
        with open(TAGS_FILE, 'w') as f:
            json.dump(tags, f, indent=2)
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating tag: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete_tag/<tag_id>', methods=['DELETE'])
@admin_required
def delete_tag(tag_id):
    try:
        # Load existing tags
        if not os.path.exists(TAGS_FILE):
            return jsonify({'error': 'No tags found'}), 404
            
        with open(TAGS_FILE, 'r') as f:
            tags = json.load(f)
        
        # Find the tag to delete
        tag_index = -1
        tag_name = None
        for i, tag in enumerate(tags):
            if tag['id'] == tag_id:
                tag_index = i
                tag_name = tag['name']
                break
        
        if tag_index == -1:
            return jsonify({'error': 'Tag not found'}), 404
        
        # Remove tag from list
        deleted_tag = tags.pop(tag_index)
        
        # Save tags
        with open(TAGS_FILE, 'w') as f:
            json.dump(tags, f, indent=2)
        
        # Update roles that use this tag
        roles = Role.get_all_roles()
        for role in roles:
            if tag_id in role.tag_access:
                role.tag_access.remove(tag_id)
                Role.update_role(role.id, tag_access=role.tag_access)
        
        # Remove tag from queries that use it
        update_queries_after_tag_delete(tag_id)
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting tag: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Function to remove a deleted tag from saved queries
def update_queries_after_tag_delete(tag_id):
    try:
        # Get all query files
        if not os.path.exists(SAVED_QUERIES_DIR):
            return
            
        for filename in os.listdir(SAVED_QUERIES_DIR):
            if filename.endswith('.json'):
                file_path = os.path.join(SAVED_QUERIES_DIR, filename)
                
                with open(file_path, 'r') as f:
                    query = json.load(f)
                
                # Check if query has tags and the deleted tag
                if 'tags' in query and tag_id in query['tags']:
                    query['tags'].remove(tag_id)
                    
                    # Save updated query
                    with open(file_path, 'w') as f:
                        json.dump(query, f, indent=2)
    except Exception as e:
        logger.error(f"Error updating queries after tag delete: {str(e)}")

@app.route('/saved_queries')
@login_required
def saved_queries():
    return render_template('saved_queries.html')

@app.route('/delete_query/<query_id>', methods=['DELETE'])
@login_required
def delete_query(query_id):
    try:
        # Get the query file
        query_file = os.path.join(SAVED_QUERIES_DIR, f"{query_id}.json")
        
        # Check if the query exists
        if not os.path.exists(query_file):
            return jsonify({'error': 'Query not found'}), 404
        
        # Check if the user has permission to delete this query
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        
        # Only allow deletion if:
        # 1. User is an admin, or
        # 2. User is the creator of the query
        is_admin = False
        if user:
            role = user.get_role()
            is_admin = role and role.name == 'Administrator'
        
        # Get query data to check ownership
        with open(query_file, 'r') as f:
            query_data = json.load(f)
        
        # Check if user has permission to delete
        if not is_admin and query_data.get('created_by') != user_id:
            return jsonify({'error': 'You do not have permission to delete this query'}), 403
        
        # Delete the query file
        os.remove(query_file)
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting query: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_settings')
@login_required
def get_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
        else:
            # Create default settings if the file doesn't exist
            settings = {
                "defaultRowsPerPage": "10",
                "defaultTimeWindow": "none"
            }
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(settings, f, indent=2)
        
        return jsonify(settings)
    except Exception as e:
        logger.error(f"Error retrieving settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/save_settings', methods=['POST'])
@login_required
def save_settings():
    try:
        settings_data = request.json
        
        # Load existing settings if available
        settings = {}
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
        
        # Update settings with new values
        settings.update(settings_data)
        
        # Save settings
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error saving settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Email address is required', 'danger')
            return render_template('forgot_password.html')
        
        # Find user by email
        user = User.get_user_by_email(email)
        if not user:
            # Don't reveal that the email doesn't exist for security reasons
            flash('If your email is registered, you will receive instructions to reset your password shortly.', 'info')
            return render_template('forgot_password.html')
        
        # Generate temporary password
        temp_password = user.generate_temp_password()
        
        # Update user in database
        User.update_user(user.id, 
                         password_hash=user.password_hash, 
                         is_temp_password=True)
        
        # Send email with temporary password
        email_sent = email_sender.send_password_reset(user.email, user.username, temp_password)
        
        if email_sent:
            flash('If your email is registered, you will receive instructions to reset your password shortly.', 'info')
        else:
            logger.error(f"Failed to send password reset email to {user.email}")
            flash('There was a problem sending the password reset email. Please try again later or contact support.', 'danger')
        
        return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token') or request.form.get('reset_token')
    
    if not token:
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('login'))
    
    # Find user with this token
    users = User.get_all_users()
    user = None
    for u in users:
        if u.reset_token == token:
            user = u
            break
    
    if not user or not user.is_reset_token_valid(token):
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or not confirm_password:
            flash('Both password fields are required', 'danger')
            return render_template('reset_password.html', reset_token=token)
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('reset_password.html', reset_token=token)
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('reset_password.html', reset_token=token)
        
        # Update user's password and clear temporary status
        User.update_user(user.id, 
                         password=new_password, 
                         is_temp_password=False, 
                         reset_token=None, 
                         reset_token_expiry=None)
        
        flash('Your password has been updated successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', reset_token=token)

@app.route('/alerts')
@login_required
def alerts_page():
    return render_template('alerts.html')

@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    try:
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        
        # Check if user is admin (can see all alerts)
        is_admin = False
        if user:
            role = user.get_role()
            is_admin = role and role.name == 'Administrator'
        
        if is_admin:
            alerts = Alert.get_all_alerts()
        else:
            # Get alerts created by this user
            alerts = Alert.get_alerts_by_user(user_id)
        
        # Convert to dict and add query info
        result = []
        for alert in alerts:
            if alert.status == 'deleted':
                continue
                
            alert_dict = alert.to_dict()
            
            # Add query name
            query = get_query_by_id(alert.query_id)
            alert_dict['query_name'] = query.get('name', 'Unknown Query') if query else 'Unknown Query'
            
            # Convert recipients to usernames
            recipient_usernames = []
            for recipient_id in alert.recipients:
                recipient = User.get_user_by_id(recipient_id)
                if recipient:
                    recipient_usernames.append(recipient.username)
            
            alert_dict['recipient_usernames'] = recipient_usernames
            
            result.append(alert_dict)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['POST'])
@login_required
def create_alert():
    try:
        data = request.json
        
        # Validate required fields
        for field in ['name', 'query_id']:
            if field not in data:
                return jsonify({'error': f"Missing required field: {field}"}), 400
        
        # Create alert
        alert = Alert.create_alert(
            name=data['name'],
            query_id=data['query_id'],
            threshold=data.get('threshold'),
            condition=data.get('condition', 'greater_than'),
            frequency=data.get('frequency', 15),
            timespan=data.get('timespan', 60),
            created_by=session.get('user_id'),
            recipients=data.get('recipients', []),
            description=data.get('description', '')
        )
        
        return jsonify(alert.to_dict()), 201
    except Exception as e:
        logger.error(f"Error creating alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>', methods=['GET'])
@login_required
def get_alert(alert_id):
    try:
        alert = Alert.get_alert_by_id(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Check if user has access to this alert
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        role = user.get_role() if user else None
        
        is_admin = role and role.name == 'Administrator'
        is_creator = alert.created_by == user_id
        
        if not (is_admin or is_creator):
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify(alert.to_dict())
    except Exception as e:
        logger.error(f"Error getting alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>', methods=['PUT'])
@login_required
def update_alert(alert_id):
    try:
        data = request.json
        
        alert = Alert.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Check if user has access to update this alert
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        role = user.get_role() if user else None
        
        is_admin = role and role.name == 'Administrator'
        is_creator = alert.created_by == user_id
        
        if not (is_admin or is_creator):
            return jsonify({'error': 'Access denied'}), 403
        
        # Update only the fields provided
        update_fields = {}
        for field in ['name', 'description', 'threshold', 'condition', 'frequency', 
                     'timespan', 'status', 'recipients']:
            if field in data:
                update_fields[field] = data[field]
        
        # Update the alert
        success = Alert.update_alert(alert_id, **update_fields)
        
        if not success:
            return jsonify({'error': 'Failed to update alert'}), 500
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<alert_id>', methods=['DELETE'])
@login_required
def delete_alert(alert_id):
    try:
        alert = Alert.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Check if user has access to delete this alert
        user_id = session.get('user_id')
        user = User.get_user_by_id(user_id)
        role = user.get_role() if user else None
        
        is_admin = role and role.name == 'Administrator'
        is_creator = alert.created_by == user_id
        
        if not (is_admin or is_creator):
            return jsonify({'error': 'Access denied'}), 403
        
        # Delete the alert
        success = Alert.delete_alert(alert_id)
        
        if not success:
            return jsonify({'error': 'Failed to delete alert'}), 500
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/triggered_alerts', methods=['GET'])
@login_required
def get_triggered_alerts():
    try:
        # Get filter parameters
        alert_id = request.args.get('alert_id')
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        severity = request.args.get('severity', 'all')
        status = request.args.get('status', 'all')
        limit = int(request.args.get('limit', 100))
        
        # Get triggered alerts with filters
        triggered_alerts = Alert.get_triggered_alerts(
            limit=limit,
            alert_id=alert_id,
            from_date=from_date,
            to_date=to_date
        )
        
        # Apply additional filters
        filtered_alerts = []
        for triggered in triggered_alerts:
            # Skip if severity doesn't match
            if severity != 'all':
                alert_severity = 'critical' if triggered.get('value', 0) > triggered.get('threshold', 0) * 1.5 else 'normal'
                if alert_severity != severity:
                    continue
            
            # Skip if status doesn't match
            if status != 'all' and triggered.get('status') != status:
                continue
            
            # Get the alert that triggered this
            alert = Alert.get_alert_by_id(triggered['alert_id'])
            if not alert:
                continue
                
            # Add alert name and query info
            triggered['alert_name'] = alert.name
            triggered['alert_description'] = alert.description
            
            query = get_query_by_id(alert.query_id)
            triggered['query_name'] = query.get('name', 'Unknown Query') if query else 'Unknown Query'
            
            filtered_alerts.append(triggered)
        
        return jsonify(filtered_alerts)
    except Exception as e:
        logger.error(f"Error getting triggered alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_query_by_id(query_id):
    """Helper to get query details by ID"""
    query_file = os.path.join(SAVED_QUERIES_DIR, f"{query_id}.json")
    
    if not os.path.exists(query_file):
        return None
    
    try:
        with open(query_file, 'r') as f:
            return json.load(f)
    except:
        return None

@app.route('/api/alert_stats')
@login_required
def get_alert_stats():
    try:
        # Get all alerts
        alerts = Alert.get_all_alerts()
        active_count = sum(1 for a in alerts if a.status == 'active')
        disabled_count = sum(1 for a in alerts if a.status == 'disabled')
        
        # Get triggered alerts in last 24 hours
        from_date = (datetime.now() - timedelta(hours=24)).isoformat()
        triggered_alerts = Alert.get_triggered_alerts(from_date=from_date)
        
        # Count critical alerts (those that exceeded their threshold by a significant amount)
        critical_count = sum(1 for a in triggered_alerts 
                           if a.get('value', 0) > a.get('threshold', 0) * 1.5)  # 50% over threshold
        
        return jsonify({
            'total_alerts': len(alerts),
            'active_alerts': active_count,
            'disabled_alerts': disabled_count,
            'triggered_last_24h': len(triggered_alerts),
            'critical_alerts': critical_count
        })
    except Exception as e:
        logger.error(f"Error getting alert stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/detections')
@login_required
def detections():
    # Get all saved queries of type 'alert'
    alerts = []
    try:
        for filename in os.listdir(SAVED_QUERIES_DIR):
            if filename.endswith('.json'):
                with open(os.path.join(SAVED_QUERIES_DIR, filename), 'r') as f:
                    query_data = json.load(f)
                    if query_data.get('type') == 'alert':
                        alerts.append(query_data)
    except Exception as e:
        logger.error(f"Error loading detections: {str(e)}")
    
    return render_template('detections.html', alerts=alerts)

@app.route('/reports')
@login_required
def reports():
    # Get all saved queries of type 'report'
    reports = []
    try:
        for filename in os.listdir(SAVED_QUERIES_DIR):
            if filename.endswith('.json'):
                with open(os.path.join(SAVED_QUERIES_DIR, filename), 'r') as f:
                    query_data = json.load(f)
                    if query_data.get('type') == 'report':
                        reports.append(query_data)
    except Exception as e:
        logger.error(f"Error loading reports: {str(e)}")
    
    return render_template('reports.html', reports=reports)

@app.route('/dashboards')
@login_required
def dashboards():
    # Get all saved queries of type 'dashboard'
    dashboards = []
    try:
        for filename in os.listdir(SAVED_QUERIES_DIR):
            if filename.endswith('.json'):
                with open(os.path.join(SAVED_QUERIES_DIR, filename), 'r') as f:
                    query_data = json.load(f)
                    if query_data.get('type') == 'dashboard':
                        dashboards.append(query_data)
    except Exception as e:
        logger.error(f"Error loading dashboards: {str(e)}")
    
    return render_template('dashboards.html', dashboards=dashboards)

@app.route('/run_report/<report_id>', methods=['POST'])
@login_required
def run_report(report_id):
    try:
        # Get the report query
        report_file = os.path.join(SAVED_QUERIES_DIR, f"{report_id}.json")
        if not os.path.exists(report_file):
            return jsonify({'error': 'Report not found'}), 404
            
        with open(report_file, 'r') as f:
            report_data = json.load(f)
            
        # Execute the query
        response = requests.post(
            'http://localhost:9200/_plugins/_sql',
            headers={'Content-Type': 'application/json'},
            json={'query': report_data['query']}
        )
        
        if response.status_code != 200:
            return jsonify({'error': 'Query execution failed'}), 500
            
        result = response.json()
        
        # Generate report based on format
        report_format = report_data.get('report_format', 'pdf')
        if report_format == 'pdf':
            # TODO: Implement PDF generation
            pass
        elif report_format == 'excel':
            # TODO: Implement Excel generation
            pass
        elif report_format == 'csv':
            # TODO: Implement CSV generation
            pass
            
        # Update last run time
        report_data['last_run'] = datetime.now().isoformat()
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        return jsonify({
            'success': True,
            'message': 'Report executed successfully'
        })
        
    except Exception as e:
        logger.error(f"Error running report: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/view_dashboard/<dashboard_id>')
@login_required
def view_dashboard(dashboard_id):
    try:
        # Get the dashboard query
        dashboard_file = os.path.join(SAVED_QUERIES_DIR, f"{dashboard_id}.json")
        if not os.path.exists(dashboard_file):
            return jsonify({'error': 'Dashboard not found'}), 404
            
        with open(dashboard_file, 'r') as f:
            dashboard_data = json.load(f)
            
        return render_template(
            'view_dashboard.html',
            dashboard=dashboard_data
        )
        
    except Exception as e:
        logger.error(f"Error viewing dashboard: {str(e)}")
        flash('Error loading dashboard')
        return redirect(url_for('dashboards'))

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html')

@app.route('/admin/indices')
@admin_required
def admin_indices():
    return render_template('admin/indices.html')

@app.route('/api/admin/indices', methods=['GET'])
def list_indices():
    try:
        client = OpenSearchClient().get_client()
        
        # Get basic index info
        indices = client.cat.indices(format='json')
        
        # Get detailed stats for each index
        result = []
        for index in indices:
            index_name = index['index']
            stats = client.indices.stats(index=index_name)
            health = client.cluster.health(index=index_name)
            
            # Get mappings to extract data types
            mappings = client.indices.get_mapping(index=index_name)
            data_types = set()
            if mappings[index_name]['mappings'].get('properties'):
                for field in mappings[index_name]['mappings']['properties'].values():
                    if field.get('type'):
                        data_types.add(field['type'])
            
            result.append({
                'name': index_name,
                'health': health['status'],
                'doc_count': stats['_all']['total']['docs']['count'],
                'size_in_bytes': stats['_all']['total']['store']['size_in_bytes'],
                'status': index.get('status', 'unknown'),
                'data_types': list(data_types)
            })
        
        return jsonify({
            'success': True,
            'indices': result
        })
        
    except Exception as e:
        logger.error(f"Error listing indices: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to list indices: {str(e)}'
        }), 500

@app.route('/api/admin/indices/<index_name>/details', methods=['GET'])
@login_required
def get_index_details(index_name):
    try:
        client = OpenSearchClient().get_client()
        
        # Get index settings and mappings
        settings = client.indices.get_settings(index=index_name)
        mappings = client.indices.get_mapping(index=index_name)
        
        # Extract data types from mappings
        data_types = set()
        if mappings[index_name]['mappings'].get('properties'):
            for field in mappings[index_name]['mappings']['properties'].values():
                if field.get('type'):
                    data_types.add(field['type'])
        
        return jsonify({
            'success': True,
            'settings': settings[index_name]['settings'],
            'mappings': mappings[index_name]['mappings'],
            'datatypes': list(data_types)
        })
        
    except Exception as e:
        logger.error(f"Error getting index details: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to get index details: {str(e)}'
        }), 500

@app.route('/api/admin/indices', methods=['POST'])
@login_required
def create_index():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        if not data.get('name'):
            return jsonify({'success': False, 'message': 'Index name is required'}), 400
        
        index_name = data['name']
        settings = data.get('settings', {})
        mappings = data.get('mappings', {})
        
        # Use the OpenSearchClient singleton
        client = OpenSearchClient().get_client()
        
        # Check if index already exists
        if client.indices.exists(index=index_name):
            return jsonify({
                'success': False, 
                'message': f'Index {index_name} already exists'
            }), 400
        
        # Create the index with settings and mappings
        create_response = client.indices.create(
            index=index_name,
            body={
                'settings': settings,
                'mappings': mappings
            }
        )
        
        if create_response.get('acknowledged'):
            return jsonify({
                'success': True, 
                'message': f'Index {index_name} created successfully'
            })
        else:
            return jsonify({
                'success': False, 
                'message': 'Index creation was not acknowledged by OpenSearch'
            }), 500
            
    except Exception as e:
        logger.error(f"Error creating index: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Failed to create index: {str(e)}'
        }), 500

@app.route('/api/admin/indices/<index_name>', methods=['DELETE'])
@login_required
def delete_index(index_name):
    try:
        client = OpenSearchClient().get_client()
        client.indices.delete(index=index_name)
        return jsonify({
            'success': True,
            'message': f'Index {index_name} deleted successfully'
        })
    except Exception as e:
        logger.error(f"Error deleting index: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to delete index: {str(e)}'
        }), 500

@app.route('/api/admin/indices/<index_name>', methods=['PUT'])
@login_required
def update_index_settings(index_name):
    try:
        data = request.get_json()
        settings = data.get('settings', {})
        
        # Update the index settings
        opensearch_client.indices.put_settings(
            index=index_name,
            body={'index': settings}
        )
        
        return jsonify({
            'success': True,
            'message': f'Index {index_name} settings updated successfully'
        })
    except Exception as e:
        logger.error(f"Error updating index settings: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# --- Connection Settings API ---

def _load_connection_settings():
    """Loads connection settings from file."""
    if os.path.exists(CONNECTIONS_FILE):
        try:
            with open(CONNECTIONS_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Error decoding {CONNECTIONS_FILE}")
            return {}
    return {}

def _save_connection_settings(settings):
    """Saves connection settings to file."""
    try:
        with open(CONNECTIONS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except IOError as e:
        logger.error(f"Error writing to {CONNECTIONS_FILE}: {e}")
        return False

@app.route('/api/admin/connections', methods=['GET'])
@admin_required
def get_connection_settings():
    settings = _load_connection_settings()
    # Never return the saved password
    settings.pop('password', None)
    return jsonify(settings)

@app.route('/api/admin/connections', methods=['POST'])
@admin_required
def save_connection_settings():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required_fields = ['host', 'port', 'use_ssl', 'verify_certs']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields (host, port, use_ssl, verify_certs)'}), 400

    # Load existing settings to merge, especially keeping password if not provided
    current_settings = _load_connection_settings()
    
    new_settings = {
        'host': data['host'],
        'port': int(data['port']),
        'username': data.get('username'),
        'use_ssl': bool(data['use_ssl']),
        'verify_certs': bool(data['verify_certs'])
    }

    # Only update password if explicitly provided in the request
    if 'password' in data and data['password']:
        new_settings['password'] = data['password']
    elif 'password' in current_settings: # Keep existing password if not updated
        new_settings['password'] = current_settings['password']

    if _save_connection_settings(new_settings):
        # Update the globally used client instance upon saving new settings
        global opensearch_client
        opensearch_client = get_client() # Re-initialize client with potentially new settings
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Failed to save settings to file'}), 500

@app.route('/api/admin/connections/test', methods=['POST'])
@admin_required
def test_connection_settings():
    """Tests connection using currently SAVED settings."""
    settings = _load_connection_settings()
    try:
        # Temporarily create a client with saved settings for testing
        test_client = OpenSearch(
            hosts=[{'host': settings.get('host', 'localhost'), 'port': settings.get('port', 9200)}],
            http_auth=(settings.get('username'), settings.get('password')) if settings.get('username') else None,
            use_ssl=settings.get('use_ssl', False),
            verify_certs=settings.get('verify_certs', False),
            connection_class=RequestsHttpConnection,
            timeout=10 # Add a timeout for the test
        )
        info = test_client.info()
        return jsonify({'success': True, 'version': info['version']['number']})
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# --- End Connection Settings API ---

@app.route('/nightwatch')
@login_required
def nightwatch():
    return render_template('nightwatch.html')

@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    try:
        data = request.json
        notes = data.get('notes', '')
        
        alert = Alert.get_alert_by_id(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Update alert status
        success = Alert.update_alert(alert_id, 
                                   status='acknowledged',
                                   acknowledged_by=session.get('user_id'),
                                   acknowledged_at=datetime.now().isoformat(),
                                   acknowledgment_notes=notes)
        
        if not success:
            return jsonify({'error': 'Failed to acknowledge alert'}), 500
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error acknowledging alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/index_management')
@login_required
def index_management():
    return render_template('index_management.html')

@app.route('/indexes')
@login_required
def indexes():
    return render_template('indexes.html')

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True) 