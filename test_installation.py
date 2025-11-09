#!/usr/bin/env python3
"""
Installation Test Script
Verifies that all components are properly installed and configured
"""

import sys
import os

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_status(test_name, passed, message=""):
    """Print test status"""
    status = "✓ PASS" if passed else "✗ FAIL"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{status}{reset} - {test_name}")
    if message:
        print(f"       {message}")

def test_python_version():
    """Test Python version"""
    version = sys.version_info
    passed = version.major == 3 and version.minor >= 8
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    print_status(
        "Python Version", 
        passed, 
        f"Found Python {version_str} (Required: 3.8+)"
    )
    return passed

def test_imports():
    """Test required package imports"""
    packages = {
        'flask': 'Flask',
        'sklearn': 'scikit-learn',
        'pandas': 'pandas',
        'numpy': 'numpy',
        'nltk': 'NLTK',
        'bs4': 'BeautifulSoup4',
        'requests': 'requests',
        'tldextract': 'tldextract',
        'langdetect': 'langdetect',
        'joblib': 'joblib'
    }
    
    all_passed = True
    for package, name in packages.items():
        try:
            __import__(package)
            print_status(f"{name} package", True)
        except ImportError as e:
            print_status(f"{name} package", False, str(e))
            all_passed = False
    
    return all_passed

def test_nltk_data():
    """Test NLTK data availability"""
    import nltk
    
    required_data = ['punkt', 'words']
    all_passed = True
    
    for data_name in required_data:
        try:
            nltk.data.find(f'tokenizers/{data_name}' if data_name == 'punkt' else f'corpora/{data_name}')
            print_status(f"NLTK {data_name} data", True)
        except LookupError:
            print_status(f"NLTK {data_name} data", False, "Run: python -c \"import nltk; nltk.download('{data_name}')\"")
            all_passed = False
    
    return all_passed

def test_core_modules():
    """Test core application modules"""
    modules = ['app', 'phishing_detector', 'train_model']
    all_passed = True
    
    for module_name in modules:
        try:
            __import__(module_name)
            print_status(f"{module_name}.py", True)
        except Exception as e:
            print_status(f"{module_name}.py", False, str(e))
            all_passed = False
    
    return all_passed

def test_directories():
    """Test required directories"""
    directories = ['templates', 'static', 'static/css', 'static/js', 'datasets', 'models']
    all_passed = True
    
    for dir_name in directories:
        exists = os.path.isdir(dir_name)
        print_status(f"Directory: {dir_name}/", exists)
        if not exists:
            all_passed = False
    
    return all_passed

def test_files():
    """Test required files"""
    files = [
        'templates/index.html',
        'static/css/style.css',
        'static/js/app.js',
        'requirements.txt',
        'README.md'
    ]
    all_passed = True
    
    for file_name in files:
        exists = os.path.isfile(file_name)
        print_status(f"File: {file_name}", exists)
        if not exists:
            all_passed = False
    
    return all_passed

def test_phishing_detector():
    """Test PhishingDetector functionality"""
    try:
        from phishing_detector import PhishingDetector
        
        detector = PhishingDetector()
        
        # Test sample email
        sample = "URGENT! Your account will be suspended. Click here now!"
        result = detector.analyze_email(sample)
        
        # Check required fields
        required_fields = ['risk_level', 'risk_score', 'urgency_tactics', 'explanation']
        has_fields = all(field in result for field in required_fields)
        
        print_status("PhishingDetector functionality", has_fields)
        if has_fields:
            print(f"       Sample analysis: Risk={result['risk_level']}, Score={result['risk_score']}")
        
        return has_fields
        
    except Exception as e:
        print_status("PhishingDetector functionality", False, str(e))
        return False

def test_flask_app():
    """Test Flask application"""
    try:
        from app import app
        
        # Check if app is created
        print_status("Flask application", app is not None)
        
        # Check routes
        routes = [rule.rule for rule in app.url_map.iter_rules()]
        has_routes = '/' in routes and '/api/analyze' in routes
        print_status("Flask routes", has_routes, f"Found {len(routes)} routes")
        
        return app is not None and has_routes
        
    except Exception as e:
        print_status("Flask application", False, str(e))
        return False

def main():
    """Run all tests"""
    print_header("Phishing Email Detector - Installation Test")
    print("This script will verify that all components are properly installed.\n")
    
    tests = [
        ("Python Version", test_python_version),
        ("Required Packages", test_imports),
        ("NLTK Data", test_nltk_data),
        ("Core Modules", test_core_modules),
        ("Directory Structure", test_directories),
        ("Required Files", test_files),
        ("Phishing Detector", test_phishing_detector),
        ("Flask Application", test_flask_app)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print_header(test_name)
        results[test_name] = test_func()
    
    # Summary
    print_header("Test Summary")
    passed = sum(results.values())
    total = len(results)
    
    print(f"\nTests Passed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 SUCCESS! All tests passed. Your installation is ready!")
        print("\nNext steps:")
        print("1. (Optional) Configure API keys in .env file")
        print("2. Run the application: python app.py")
        print("3. Open http://localhost:5000 in your browser")
        return 0
    else:
        print("\n⚠️  WARNING! Some tests failed. Please fix the issues above.")
        print("\nCommon fixes:")
        print("1. Install missing packages: pip install -r requirements.txt")
        print("2. Download NLTK data: python -c \"import nltk; nltk.download('punkt'); nltk.download('words')\"")
        print("3. Ensure all files are in the correct locations")
        return 1

if __name__ == "__main__":
    sys.exit(main())
