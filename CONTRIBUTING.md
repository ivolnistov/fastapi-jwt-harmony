# Contributing to FastAPI JWT Harmony

Thank you for your interest in contributing to FastAPI JWT Harmony! 🎉

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Documentation](#documentation)

## 🚀 Getting Started

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) for package management
- Git

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/fastapi-jwt-harmony.git
   cd fastapi-jwt-harmony
   ```

2. **Install dependencies**
   ```bash
   uv sync --dev
   ```

3. **Verify installation**
   ```bash
   uv run pytest --version
   uv run ruff --version
   uv run mypy --version
   ```

## 🧪 Testing

We maintain 100% test coverage. All new features must include comprehensive tests.

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=fastapi_jwt_harmony --cov-report=html

# Run specific test file
uv run pytest tests/test_config.py

# Run specific test
uv run pytest tests/test_config.py::test_default_config

# Run tests with verbose output
uv run pytest -v
```

### Writing Tests

- Tests are located in the `tests/` directory
- Use descriptive test names that explain what is being tested
- Include both positive and negative test cases
- Mock external dependencies appropriately
- Test edge cases and error conditions

Example test structure:
```python
def test_feature_name_should_do_expected_behavior():
    # Arrange
    user = SimpleUser(id="test")
    config = JWTHarmonyConfig(authjwt_secret_key="secret")

    # Act
    result = some_function(user, config)

    # Assert
    assert result.is_valid
    assert result.user_id == "test"
```

## 🔍 Code Quality

We use multiple tools to ensure code quality:

### Linting and Formatting

```bash
# Check code style
uv run ruff check src/

# Auto-fix issues
uv run ruff check src/ --fix

# Format code
uv run ruff format src/

# Type checking
uv run mypy src/fastapi_jwt_harmony

# Additional checks
uv run pylint src/fastapi_jwt_harmony
```

### Pre-commit Hooks

We recommend setting up pre-commit hooks:

```bash
uv run pre-commit install
```

This will run checks automatically before each commit.

## 📝 Code Style

### General Guidelines

- Follow PEP 8 style guide
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions focused and small
- Use descriptive variable names
- Prefer composition over inheritance

### Type Hints

```python
from typing import Optional, Union
from pydantic import BaseModel

def create_token(
    user: BaseModel,
    expires: Optional[timedelta] = None,
    fresh: bool = False
) -> str:
    """Create a JWT token for the given user."""
    pass
```

### Docstring Style

Use Google-style docstrings:

```python
def validate_token(token: str, secret: str) -> dict[str, Any]:
    """Validate and decode a JWT token.

    Args:
        token: The JWT token to validate
        secret: Secret key for validation

    Returns:
        Decoded token payload

    Raises:
        JWTDecodeError: If token is invalid
        TokenExpired: If token has expired
    """
    pass
```

### Import Organization

- Standard library imports first
- Third-party imports second
- Local imports last
- Use absolute imports
- Sort imports alphabetically within each group

```python
import hmac
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, Request
from pydantic import BaseModel

from .exceptions import JWTHarmonyException
from .utils import get_jwt_identifier
```

## 🎯 Submitting Changes

### Before Submitting

1. **Run the full test suite**
   ```bash
   uv run pytest
   ```

2. **Check code quality**
   ```bash
   uv run ruff check src/
   uv run mypy src/fastapi_jwt_harmony
   uv run pylint src/fastapi_jwt_harmony
   ```

3. **Update documentation** if needed

4. **Add changelog entry** for significant changes

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clear, focused commits
   - Include tests for new functionality
   - Update documentation as needed

3. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Fill out the PR template**
   - Describe what changes you made
   - Explain why the changes are needed
   - Reference any related issues
   - Add screenshots if applicable

### PR Requirements

- ✅ All tests must pass
- ✅ Code coverage must not decrease
- ✅ All linting checks must pass
- ✅ Type checking must pass
- ✅ Documentation must be updated
- ✅ Changelog entry for significant changes

## 📚 Documentation

### Code Documentation

- Write clear docstrings for all public APIs
- Include type hints for better IDE support
- Add inline comments for complex logic
- Keep comments up-to-date with code changes

### User Documentation

- Update README.md for new features
- Add examples for new functionality
- Update configuration documentation
- Consider adding migration guides for breaking changes

### Example Documentation

When adding new features, include practical examples:

```python
# ✅ Good: Clear example with context
@app.post("/login")
def login(Authorize: JWTHarmony[User] = Depends()):
    """Login endpoint that creates JWT tokens."""
    user = User(id="123", username="john")
    access_token = Authorize.create_access_token(user_claims=user)
    return {"access_token": access_token}

# ❌ Bad: No context or explanation
def login():
    return create_token()
```

## 🐛 Reporting Issues

### Bug Reports

Include:
- Python version
- FastAPI version
- Library version
- Minimal reproduction code
- Expected vs actual behavior
- Full error traceback

### Feature Requests

Include:
- Use case description
- Proposed API design
- Examples of how it would be used
- Alternatives considered

## 🏗️ Architecture Guidelines

### Core Principles

1. **Type Safety**: Everything should be properly typed
2. **Dependency Injection**: Use FastAPI's DI system
3. **Pydantic Integration**: Leverage Pydantic for validation
4. **Security First**: Default to secure configurations
5. **Backward Compatibility**: Avoid breaking changes when possible

### Code Organization

```
src/fastapi_jwt_harmony/
├── __init__.py          # Public API exports
├── base.py              # Core JWT logic
├── fastapi_auth.py      # HTTP authentication
├── websocket_auth.py    # WebSocket authentication
├── config.py            # Configuration models
├── exceptions.py        # Custom exceptions
├── utils.py             # Utility functions
└── constants.py         # Constants and enums
```

### Adding New Features

1. **Start with tests** - write failing tests first
2. **Implement the feature** - focus on the core logic
3. **Add documentation** - include examples and docstrings
4. **Update configuration** - if new settings are needed
5. **Test edge cases** - ensure robust error handling

## 💡 Getting Help

- Open an issue for questions
- Check existing issues and PRs
- Join discussions in issues
- Ask questions in pull requests

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributors section
- CHANGELOG.md for significant features
- GitHub contributors page

Thank you for helping make FastAPI JWT Harmony better! 🚀
