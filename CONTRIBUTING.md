# Contributing to Phishing Email Detector

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🌟 Ways to Contribute

### 1. Report Bugs
- Use GitHub Issues
- Include detailed description
- Provide sample email (sanitized)
- Include error messages
- Specify your environment (OS, Python version)

### 2. Suggest Features
- Open a GitHub Issue with the "feature request" label
- Describe the feature and use case
- Explain why it would be useful

### 3. Submit Code
- Fork the repository
- Create a feature branch
- Write clean, documented code
- Add tests if applicable
- Submit a Pull Request

### 4. Improve Documentation
- Fix typos or unclear explanations
- Add examples
- Translate to other languages
- Improve code comments

### 5. Share Datasets
- Contribute public phishing datasets
- Help curate and label data
- Ensure no sensitive information

## 📋 Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/yourusername/phishing-email-detector.git
cd phishing-email-detector
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### 4. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

## 🎨 Code Style

### Python
- Follow PEP 8 style guide
- Use type hints where applicable
- Write docstrings for functions and classes
- Keep functions focused and small

Example:
```python
def analyze_sender(self, sender: str) -> Dict[str, Any]:
    """
    Analyze sender email address for suspicious patterns
    
    Args:
        sender: Email address to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    # Implementation here
```

### JavaScript
- Use ES6+ features
- Use meaningful variable names
- Add comments for complex logic
- Keep functions pure when possible

### HTML/CSS
- Use semantic HTML
- Follow BEM naming convention for CSS classes
- Maintain responsive design
- Keep accessibility in mind

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test file
pytest tests/test_detector.py
```

### Writing Tests

Create tests in the `tests/` directory:

```python
def test_urgency_detection():
    detector = PhishingDetector()
    result = detector._check_urgency("URGENT: Act now!")
    assert result['detected'] == True
```

## 📝 Commit Messages

Use clear, descriptive commit messages:

```
feat: Add attachment analysis feature
fix: Correct sender domain validation
docs: Update installation instructions
style: Format code according to PEP 8
refactor: Simplify risk calculation logic
test: Add tests for URL analysis
```

## 🔄 Pull Request Process

1. **Update Documentation**
   - Update README if needed
   - Add docstrings to new functions
   - Update CHANGELOG

2. **Test Your Changes**
   - Run all tests
   - Test manually with various inputs
   - Check for edge cases

3. **Create Pull Request**
   - Provide clear description
   - Reference related issues
   - Include screenshots if UI changes
   - Wait for review

4. **Address Feedback**
   - Respond to review comments
   - Make requested changes
   - Re-request review

## 🐛 Bug Reports

Include:
- **Description**: Clear and concise description
- **Steps to Reproduce**: Detailed steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Environment**: OS, Python version, browser
- **Sample Data**: Sanitized email example (if applicable)
- **Error Messages**: Full error output

## 💡 Feature Requests

Include:
- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Additional Context**: Screenshots, mockups, etc.

## 🔒 Security

If you discover a security vulnerability:
- **DO NOT** open a public issue
- Email the maintainers directly
- Provide detailed information
- Allow time for a fix before public disclosure

## 📜 Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help others learn and grow

## 🎓 Learning Resources

New to contributing? Check out:
- [GitHub Flow](https://guides.github.com/introduction/flow/)
- [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/)
- [Python PEP 8 Style Guide](https://www.python.org/dev/peps/pep-0008/)

## 🙏 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Given our eternal gratitude! 🎉

## 📞 Questions?

- Open a GitHub Discussion
- Comment on relevant issues
- Reach out to maintainers

Thank you for making the internet safer! 🛡️
