from opensearchpy import OpenSearch, RequestsHttpConnection
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class OpenSearchService:
    _instance = None
    _client = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OpenSearchService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._client is None:
            self._initialize_client()

    def _initialize_client(self):
        """Initialize the OpenSearch client with configuration from Flask app."""
        try:
            self._client = OpenSearch(
                hosts=[{
                    'host': current_app.config['OPENSEARCH_HOST'],
                    'port': current_app.config['OPENSEARCH_PORT']
                }],
                http_auth=(
                    current_app.config['OPENSEARCH_USER'],
                    current_app.config['OPENSEARCH_PASSWORD']
                ),
                use_ssl=current_app.config['OPENSEARCH_USE_SSL'],
                verify_certs=False,
                connection_class=RequestsHttpConnection
            )
            logger.info("OpenSearch client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OpenSearch client: {str(e)}")
            raise

    def get_client(self):
        """Get the OpenSearch client instance."""
        return self._client

    def create_index(self, index_name, settings=None, mappings=None):
        """Create a new index with optional settings and mappings."""
        try:
            body = {}
            if settings:
                body['settings'] = settings
            if mappings:
                body['mappings'] = mappings

            response = self._client.indices.create(
                index=index_name,
                body=body if body else None
            )
            logger.info(f"Index '{index_name}' created successfully")
            return response
        except Exception as e:
            logger.error(f"Failed to create index '{index_name}': {str(e)}")
            raise

    def delete_index(self, index_name):
        """Delete an index."""
        try:
            response = self._client.indices.delete(index=index_name)
            logger.info(f"Index '{index_name}' deleted successfully")
            return response
        except Exception as e:
            logger.error(f"Failed to delete index '{index_name}': {str(e)}")
            raise

    def index_exists(self, index_name):
        """Check if an index exists."""
        try:
            return self._client.indices.exists(index=index_name)
        except Exception as e:
            logger.error(f"Failed to check if index '{index_name}' exists: {str(e)}")
            raise

    def get_index_stats(self, index_name=None):
        """Get statistics for one or all indices."""
        try:
            return self._client.indices.stats(index=index_name)
        except Exception as e:
            logger.error(f"Failed to get index stats: {str(e)}")
            raise

    def get_index_settings(self, index_name):
        """Get settings for an index."""
        try:
            return self._client.indices.get_settings(index=index_name)
        except Exception as e:
            logger.error(f"Failed to get settings for index '{index_name}': {str(e)}")
            raise

    def get_index_mapping(self, index_name):
        """Get mapping for an index."""
        try:
            return self._client.indices.get_mapping(index=index_name)
        except Exception as e:
            logger.error(f"Failed to get mapping for index '{index_name}': {str(e)}")
            raise

    def index_document(self, index_name, document, doc_id=None):
        """Index a document."""
        try:
            return self._client.index(
                index=index_name,
                body=document,
                id=doc_id,
                refresh=True
            )
        except Exception as e:
            logger.error(f"Failed to index document in '{index_name}': {str(e)}")
            raise

    def search(self, index_name, query):
        """Search documents in an index."""
        try:
            return self._client.search(
                index=index_name,
                body=query
            )
        except Exception as e:
            logger.error(f"Failed to search in index '{index_name}': {str(e)}")
            raise

    def bulk_index(self, index_name, documents):
        """Bulk index multiple documents."""
        try:
            body = []
            for doc in documents:
                body.extend([
                    {'index': {'_index': index_name}},
                    doc
                ])
            return self._client.bulk(body=body, refresh=True)
        except Exception as e:
            logger.error(f"Failed to bulk index documents in '{index_name}': {str(e)}")
            raise 