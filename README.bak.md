# Pattern Analysis Application

A web-based application for analyzing log patterns, managing queries, and monitoring security events using OpenSearch. Built with Flask and modern security practices, this tool helps teams efficiently analyze logs, create dashboards, and set up automated alerts.

## Features

- **Pattern Analysis**
  - Regex-based log parsing and pattern detection
  - Customizable pattern definitions
  - Batch processing support
  - Export analysis results
  
- **Data Security**
  - Automated sensitive data detection
  - Configurable data obscuring rules
  - Audit logging of all operations
  - Data encryption at rest and in transit
  
- **Query Management**
  - Support for SQL, PPL, and DSL queries
  - Query templates and variables
  - Query version history
  - Export results in multiple formats
  
- **Dashboards**
  - Interactive visualization builder
  - Multiple chart types (line, bar, pie, table)
  - Real-time data updates
  - Custom dashboard layouts
  
- **Alerts**
  - Threshold-based alerting
  - Schedule-based checks
  - Multiple notification channels
  - Alert history and analytics
  
- **User Management**
  - Role-based access control (RBAC)
  - Two-factor authentication (2FA)
  - Single sign-on (SSO) support
  - Password policy enforcement
  
- **OpenSearch Integration**
  - Direct OpenSearch querying
  - Index management
  - Data replication support
  - Performance optimization

## Project Structure

```
├── app.py                 # Main Flask application
├── models/               # Database models
│   ├── __init__.py
│   └── alert.py         # Alert model definition
├── utils/               # Utility modules
│   ├── __init__.py
│   ├── alert_checker.py # Alert monitoring system
│   ├── data_obscurer.py # Data anonymization
│   ├── email_sender.py  # Email notifications
│   ├── opensearch_client.py # OpenSearch interface
│   └── regex_parser.py  # Log pattern parsing
├── templates/           # HTML templates
│   ├── admin/          # Admin panel templates
│   ├── base.html       # Base template
│   ├── login.html      # Authentication templates
│   └── ...             # Other page templates
├── settings/           # Application settings
├── saved_queries/      # Stored query definitions
├── uploads/           # Temporary file uploads
├── docker-compose.yml  # Docker configuration
├── opensearch.Dockerfile # OpenSearch container
├── opensearch.yml     # OpenSearch configuration
├── requirements.txt   # Python dependencies
└── .env              # Environment variables
```

## Prerequisites

- Python 3.8 or higher
- Docker and Docker Compose
- 4GB RAM minimum (8GB recommended)
- OpenSearch-compatible system

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/pattern-analysis.git
   cd pattern-analysis
   ```

2. Create and activate virtual environment:
   ```bash
   # Linux/Mac
   python -m venv venv
   source venv/bin/activate

   # Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   # Copy example environment file
   cp .env.example .env

   # Edit .env with your settings
   SECRET_KEY=your-secure-secret-key
   OPENSEARCH_HOST=localhost
   OPENSEARCH_PORT=9200
   OPENSEARCH_USER=admin
   OPENSEARCH_PASSWORD=admin
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-specific-password
   ```

5. Start OpenSearch using Docker:
   ```bash
   # Start OpenSearch and dependencies
   docker-compose up -d

   # Verify containers are running
   docker-compose ps
   ```

6. Initialize the application:
   ```bash
   # Create initial database structure
   python init_db.py

   # Create admin user
   python create_admin.py
   ```

## Configuration

### OpenSearch Settings

Edit `opensearch.yml` to configure:
- Memory allocation
- Network settings
- Security settings
- Index settings

Example configuration:
```yaml
cluster.name: pattern-analysis
node.name: pattern-analysis-node
network.host: 0.0.0.0
discovery.type: single-node
```

### Application Settings

Key settings in `settings/config.py`:
```python
# Query timeout in seconds
QUERY_TIMEOUT = 30

# Maximum upload file size
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# Session timeout
PERMANENT_SESSION_LIFETIME = 3600
```

## Usage

### Pattern Analysis

1. Navigate to Pattern Analysis section
2. Upload log file or paste log content
3. Define or select existing patterns
4. Configure parsing options
5. Run analysis
6. Export or save results

### Query Management

1. Create new query:
   - Select query type (SQL/PPL/DSL)
   - Write query
   - Test and validate
   - Save with metadata

2. Execute saved queries:
   - Select saved query
   - Modify parameters if needed
   - Run query
   - View/export results

### Dashboards

1. Create dashboard:
   - Choose layout
   - Add widgets
   - Configure data sources
   - Set refresh interval

2. Widget types:
   - Tables
   - Line charts
   - Bar charts
   - Pie charts
   - Metrics
   - Heat maps

### Alerts

1. Create alert:
   - Define query
   - Set conditions
   - Configure schedule
   - Set notifications

2. Alert actions:
   - Email notifications
   - Webhook calls
   - Log entries
   - Status updates

## Security

### Authentication

- Password requirements:
  - Minimum 12 characters
  - Mix of uppercase, lowercase, numbers, symbols
  - Regular password rotation

- 2FA options:
  - TOTP (Google Authenticator)
  - Email codes
  - Hardware keys

### Authorization

Role-based access with predefined roles:
- Admin: Full system access
- Analyst: Query and dashboard access
- User: View-only access
- Custom roles available

### Data Protection

- All sensitive data is encrypted at rest
- TLS for all connections
- Automatic sensitive data detection
- Configurable data retention policies

## Troubleshooting

Common issues and solutions:

1. OpenSearch connection fails:
   - Check Docker container status
   - Verify network settings
   - Check credentials in .env

2. Query timeout errors:
   - Adjust timeout settings
   - Optimize query
   - Check index performance

3. Dashboard loading slow:
   - Reduce widget count
   - Optimize queries
   - Adjust refresh interval

## Development

### Testing

Run tests:
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_parser.py

# Run with coverage
pytest --cov=app tests/
```

### Code Style

Format code:
```bash
# Format code
black .

# Check style
flake8
```

### Contributing

1. Fork repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

## Support

- GitHub Issues: Bug reports and feature requests
- Email Support: support@example.com
- Documentation: /docs directory

## License

This project is licensed under the MIT License. See the LICENSE file for details. 