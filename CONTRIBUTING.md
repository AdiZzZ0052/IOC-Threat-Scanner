# Contributing to IOC Threat Scanner

First off, thank you for considering contributing to IOC Threat Scanner! It's people like you that make this tool better for the cybersecurity community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security Contributions](#security-contributions)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- A GitHub account

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
```bash
git clone https://github.com/YOUR-USERNAME/IOC-Threat-Scanner.git
cd IOC-Threat-Scanner
```

3. Add the upstream remote:
```bash
git remote add upstream https://github.com/AdiZzZ0052/IOC-Threat-Scanner.git
```

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates.

**When reporting a bug, include:**

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Screenshots if applicable
- Your environment (OS, Python version, etc.)
- Any error messages or logs

### Suggesting Features

Feature suggestions are welcome! Please provide:

- A clear description of the feature
- The problem it solves
- Potential implementation approach
- Any relevant examples from other tools

### Adding New Threat Intelligence Sources

We're always looking to integrate new threat intelligence APIs. If you'd like to add support for a new source:

1. Open an issue first to discuss the integration
2. Ensure the API has a free tier available
3. Follow the existing pattern in the codebase
4. Include proper error handling and rate limiting

### Improving Documentation

Documentation improvements are always welcome:

- Fix typos or unclear explanations
- Add usage examples
- Improve code comments
- Create tutorials or guides

## Development Setup

1. **Create a virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

2. **Install development dependencies:**
```bash
pip install -r requirements-dev.txt
```

3. **Set up pre-commit hooks (optional but recommended):**
```bash
pip install pre-commit
pre-commit install
```

4. **Run tests:**
```bash
pytest
```

5. **Run linting:**
```bash
flake8 ioc_scanner.py
black --check ioc_scanner.py
```

## Style Guidelines

### Python Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Maximum line length: 100 characters
- Use type hints where appropriate
- Document functions with docstrings

### Example:
```python
def sanitize_ioc(ioc: str) -> Optional[str]:
    """
    Validate and sanitize IOC input to prevent injection attacks.

    Args:
        ioc: The indicator of compromise to sanitize

    Returns:
        Clean IOC string or None if invalid
    """
    if not ioc:
        return None
    # ... implementation
```

### Security Guidelines

When contributing code, always consider security:

- **Input Validation**: Always sanitize user input
- **Output Encoding**: Escape HTML to prevent XSS
- **API Security**: Never log or expose API keys
- **Error Handling**: Don't expose sensitive info in error messages

## Commit Messages

Use clear, descriptive commit messages following this format:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

### Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding tests
- `security`: Security improvements
- `perf`: Performance improvements

### Examples:
```
feat(scanner): add support for SHA512 hashes
fix(api): handle rate limiting for VirusTotal API
docs(readme): add installation instructions for Linux
security(input): improve IOC sanitization
```

## Pull Request Process

1. **Create a feature branch:**
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes and commit:**
```bash
git add .
git commit -m "feat(scope): description"
```

3. **Keep your branch updated:**
```bash
git fetch upstream
git rebase upstream/main
```

4. **Push to your fork:**
```bash
git push origin feature/your-feature-name
```

5. **Create a Pull Request** on GitHub with:
   - Clear title and description
   - Reference to related issues
   - Screenshots for UI changes
   - Test results

### PR Checklist

- [ ] Code follows the style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
- [ ] No sensitive data in commits
- [ ] Tests pass locally
- [ ] Security considerations addressed

## Security Contributions

### Reporting Security Vulnerabilities

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
- Email: Create a private security advisory on GitHub
- Follow responsible disclosure practices

See [SECURITY.md](SECURITY.md) for more details.

### Security Improvements

Security improvements are highly valued. When submitting security-related PRs:

1. Clearly describe the vulnerability being addressed
2. Explain the impact and severity
3. Provide test cases demonstrating the fix
4. Follow secure coding practices

---

## Questions?

Feel free to open an issue with the `question` label if you need help getting started.

Thank you for contributing!

— **Adi Cohen** ([@AdiZzZ0052](https://github.com/AdiZzZ0052))
