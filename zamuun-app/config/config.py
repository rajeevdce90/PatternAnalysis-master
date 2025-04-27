import os

# Application configuration
class Config:
    # Flask app configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-key'
    DEBUG = os.environ.get('DEBUG') or True
    
    # OpenSearch configuration
    OPENSEARCH_HOST = os.environ.get('OPENSEARCH_HOST') or 'localhost'
    OPENSEARCH_PORT = os.environ.get('OPENSEARCH_PORT') or 9200
    OPENSEARCH_USERNAME = os.environ.get('OPENSEARCH_USERNAME') or ''
    OPENSEARCH_PASSWORD = os.environ.get('OPENSEARCH_PASSWORD') or ''
    OPENSEARCH_USE_HTTPS = os.environ.get('OPENSEARCH_USE_HTTPS') == 'true' or False
    
    # Default index settings
    DEFAULT_INDEX = 'pa_logs'
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Saved queries and settings directories
    SAVED_QUERIES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'saved_queries')
    SETTINGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings')
    SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'app_settings.json')
    
    # Ensure directories exist
    @classmethod
    def init_app(cls, app):
        os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(cls.SAVED_QUERIES_DIR, exist_ok=True)
        os.makedirs(cls.SETTINGS_DIR, exist_ok=True) 