from flask import Flask
from config.config import Config
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app(config_class=Config):
    """Application factory function"""
    app = Flask(__name__, 
                template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates'),
                static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static'))
    
    # Load configuration
    app.config.from_object(config_class)
    
    # Initialize app with config settings
    config_class.init_app(app)
    
    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.search import search_bp
    from app.routes.saved_queries import saved_queries_bp
    from app.routes.settings import settings_bp
    from app.routes.api import api_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(saved_queries_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Log application startup
    logger.info(f"Zamuun Analysis App starting. Upload directory: {app.config['UPLOAD_FOLDER']}")
    
    return app 