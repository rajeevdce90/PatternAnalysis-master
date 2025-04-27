# Contributing to Pattern Analysis

Thank you for your interest in contributing to the Pattern Analysis project! This document provides guidelines and setup instructions for contributors.

## Development Setup

### Prerequisites
- Python 3.8 or higher
- Docker and Docker Compose
- Git

### Local Development Environment

1. **Clone the repository**
```bash
git clone <repository-url>
cd pattern-analysis
```

2. **Set up Python virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Configure environment variables**
Copy `.env.example` to `.env` and adjust settings as needed:
```bash
cp .env.example .env
```

4. **Start Docker services**
```bash
docker-compose up -d opensearch logstash
```

5. **Run the development server**
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Development Workflow

1. **Create a new branch for your feature**
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**
- Follow the project's coding style
- Add tests for new features
- Update documentation as needed

3. **Run tests**
```bash
pytest
```

4. **Submit a Pull Request**
- Provide a clear description of the changes
- Reference any related issues
- Ensure all tests pass
- Update relevant documentation

## Code Style Guidelines

- Follow PEP 8 guidelines for Python code
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Comment complex logic
- Keep functions focused and concise

## Testing

- Write unit tests for new features
- Ensure existing tests pass
- Test edge cases
- Include integration tests where appropriate

## Documentation

- Update README.md for significant changes
- Document new features and APIs
- Include examples where helpful
- Keep documentation clear and concise

## Getting Help

- Create an issue for bugs or feature requests
- Ask questions in the project's discussion forum
- Review existing issues and pull requests

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Provide constructive feedback
- Follow the project's code of conduct

Thank you for contributing to Pattern Analysis! 