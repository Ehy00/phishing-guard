"""
Flask Web Application for Phishing Email Detection
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from phishing_detector import PhishingDetector
import os
import json

app = Flask(__name__)
CORS(app)

# Initialize detector with optional API key
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', None)
detector = PhishingDetector(virustotal_api_key=VT_API_KEY)


@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """
    Analyze an email for phishing indicators
    
    Expected JSON payload:
    {
        "email_content": "Email body text",
        "sender": "sender@example.com",
        "subject": "Email subject"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'email_content' not in data:
            return jsonify({
                'error': 'Missing required field: email_content'
            }), 400
        
        email_content = data.get('email_content', '')
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        
        if not email_content.strip():
            return jsonify({
                'error': 'Email content cannot be empty'
            }), 400
        
        # Perform analysis
        results = detector.analyze_email(
            email_content=email_content,
            sender=sender,
            subject=subject
        )
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({
            'error': f'Analysis failed: {str(e)}'
        }), 500


@app.route('/api/check-url', methods=['POST'])
def check_url():
    """
    Check URL reputation using VirusTotal API
    
    Expected JSON payload:
    {
        "url": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing required field: url'
            }), 400
        
        url = data.get('url', '')
        
        if not url.strip():
            return jsonify({
                'error': 'URL cannot be empty'
            }), 400
        
        # Check URL reputation
        result = detector.check_url_reputation(url)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f'URL check failed: {str(e)}'
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'api_key_configured': VT_API_KEY is not None
    })


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║         Phishing Email Detection System                  ║
    ║                                                           ║
    ║  Server running on: http://localhost:{port}             ║
    ║  VirusTotal API: {'✓ Configured' if VT_API_KEY else '✗ Not configured'}                    ║
    ║                                                           ║
    ║  Press CTRL+C to quit                                    ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
