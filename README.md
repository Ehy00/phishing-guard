# 🛡️ Phishing Email Detector

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

**An advanced AI-powered tool for detecting phishing attempts in emails**

[Features](#features) • [Demo](#demo) • [Installation](#installation) • [Usage](#usage) • [API](#api) • [Training](#training) • [Contributing](#contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Training Your Own Model](#training-your-own-model)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

The **Phishing Email Detector** is a sophisticated, AI-powered web application that analyzes emails for phishing indicators and provides comprehensive risk assessments. Built with modern machine learning techniques and rule-based detection, it identifies suspicious patterns that could indicate phishing attempts.

### Why This Tool?

Phishing attacks are one of the most common cyber threats, costing billions annually. This tool helps:
- 🔍 **Identify suspicious emails** before you interact with them
- 🎓 **Learn** what makes emails suspicious
- 🛡️ **Protect** sensitive information from theft
- 📊 **Analyze** emails from your spam folder to understand attack patterns

---

## ✨ Features

### 🚨 Multi-Factor Detection

1. **Urgency Tactics Detection**
   - Identifies pressure phrases like "act now", "urgent", "expires today"
   - Detects excessive exclamation marks and ALL CAPS usage
   - Analyzes psychological manipulation techniques

2. **Sender Domain Analysis**
   - Validates sender email addresses
   - Detects typosquatting (e.g., `paypa1.com` vs `paypal.com`)
   - Identifies suspicious TLDs (.xyz, .top, .tk, etc.)
   - Checks for domain spoofing attempts

3. **Sensitive Information Requests**
   - Detects requests for passwords, credit cards, SSN
   - Identifies form-like input patterns
   - Flags banking and personal information solicitation

4. **Link Analysis**
   - Examines URLs for suspicious patterns
   - Detects IP addresses instead of domain names
   - Identifies URL shorteners and redirect tricks
   - Checks for link text vs. actual URL mismatches

5. **Grammar & Language Analysis**
   - Detects spelling and grammar issues
   - Identifies inconsistent capitalization
   - Checks for language mismatches
   - Analyzes text quality and professionalism

### 🔗 URL Reputation Checking

- **VirusTotal API Integration** (optional)
- Real-time URL scanning
- Reputation scores from 70+ antivirus engines
- Malicious link detection

### 📊 Risk Scoring System

- **0-29**: Low Risk (✅)
- **30-59**: Medium Risk (⚠️)
- **60-100**: High Risk (🚨)

Provides detailed explanations for each risk assessment.

### 🎨 Beautiful Modern UI

- Dark-themed, responsive design
- Real-time analysis feedback
- Intuitive risk visualization
- Mobile-friendly interface
- Animated results display

---

## 🛠️ Technology Stack

### Backend
- **Python 3.8+**: Core logic and ML models
- **Flask**: Web framework and REST API
- **scikit-learn**: Machine learning algorithms
- **NLTK**: Natural language processing
- **BeautifulSoup4**: HTML parsing
- **TLD Extract**: Domain analysis

### Frontend
- **HTML5**: Structure
- **CSS3**: Modern styling with gradients and animations
- **JavaScript**: Interactive functionality
- **Fetch API**: Asynchronous communication

### Machine Learning
- **TF-IDF Vectorization**: Text feature extraction
- **Random Forest**: Ensemble learning
- **Gradient Boosting**: Advanced classification
- **Logistic Regression**: Baseline model
- **Custom Feature Engineering**: Domain-specific indicators

---

## 📥 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git
- (Optional) VirusTotal API key for URL scanning

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-email-detector.git
cd phishing-email-detector
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Download NLTK Data

```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('words')"
```

### Step 5: (Optional) Configure API Keys

Create a `.env` file in the project root:

```bash
# .env file
VIRUSTOTAL_API_KEY=your_api_key_here
DEBUG=True
PORT=5000
```

Get a free VirusTotal API key at: https://www.virustotal.com/gui/join-us

---

## 🚀 Quick Start

### Running the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

### First-Time Setup

1. Open your browser and navigate to `http://localhost:5000`
2. Click **"Load Example"** to see a sample phishing email
3. Click **"Analyze Email"** to see the detection in action
4. Try pasting your own emails from your spam folder!

---

## 📖 Usage

### Web Interface

1. **Open the application** in your browser
2. **Enter email details**:
   - Sender email (optional)
   - Subject line (optional)
   - Email content (required)
3. **Click "Analyze Email"**
4. **Review the results**:
   - Risk level (Low/Medium/High)
   - Risk score (0-100)
   - Detailed analysis of each factor
   - Recommendations

### Example Analysis

```
Input:
From: security@paypa1-verify.xyz
Subject: URGENT: Verify Your Account NOW!
Content: Your PayPal account has been suspended...

Output:
Risk Level: HIGH (🚨)
Risk Score: 85/100

Issues Detected:
✗ Urgency tactics (3 keywords found)
✗ Suspicious sender domain (typosquatting)
✗ Requests sensitive information (password, SSN)
✗ Suspicious links detected
✗ Grammar issues found
```

---

## 🔌 API Documentation

### Analyze Email Endpoint

**POST** `/api/analyze`

Analyze an email for phishing indicators.

**Request Body:**
```json
{
  "email_content": "Email body text...",
  "sender": "sender@example.com",
  "subject": "Email subject"
}
```

**Response:**
```json
{
  "risk_level": "High",
  "risk_score": 85,
  "urgency_tactics": {
    "detected": true,
    "urgency_keywords": ["urgent", "immediately"],
    "severity": "high"
  },
  "sender_analysis": {
    "detected": true,
    "issues": ["Suspicious TLD: .xyz"],
    "severity": "high"
  },
  "sensitive_info_requests": {
    "detected": true,
    "requested_info": ["password", "social security"],
    "severity": "high"
  },
  "link_analysis": {
    "detected": true,
    "suspicious_urls": [...],
    "severity": "high"
  },
  "grammar_issues": {
    "detected": true,
    "issues": ["Inconsistent capitalization"],
    "severity": "medium"
  },
  "explanation": "Detailed explanation..."
}
```

### Check URL Endpoint

**POST** `/api/check-url`

Check URL reputation using VirusTotal.

**Request Body:**
```json
{
  "url": "https://suspicious-site.xyz"
}
```

**Response:**
```json
{
  "available": true,
  "malicious": 15,
  "suspicious": 3,
  "harmless": 52,
  "is_threat": true
}
```

### Health Check Endpoint

**GET** `/api/health`

Check API status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "api_key_configured": true
}
```

---

## 🎓 Training Your Own Model

### Using Public Datasets

The tool supports training with public phishing datasets:

1. **Nazario Phishing Corpus**: http://monkey.org/~jose/phishing/
2. **APWG**: https://apwg.org/
3. **Kaggle Phishing Emails**: https://www.kaggle.com/datasets/subhajournal/phishingemails

### Training Steps

1. **Prepare your dataset**:
   - Place CSV files in the `datasets/` directory
   - Format: columns named `text` and `is_phishing`
   - See `datasets/README.md` for details

2. **Run the training script**:
   ```bash
   python train_model.py
   ```

3. **Review results**:
   - The script will train multiple models
   - Compare accuracy scores
   - Best model is automatically saved

4. **Model files** will be saved to `models/`:
   - `phishing_model.pkl`: Trained classifier
   - `vectorizer.pkl`: TF-IDF vectorizer

### Dataset Format

```csv
text,is_phishing
"URGENT: Your account will be suspended...",1
"Hi team, meeting scheduled for tomorrow...",0
"Click here to verify your password immediately!",1
"Your package has been delivered successfully.",0
```

### Training Output Example

```
Training Phishing Detection Model
======================================
Training set: 800 samples
Test set: 200 samples

Training Random Forest...
Random Forest Accuracy: 0.9450

Training Gradient Boosting...
Gradient Boosting Accuracy: 0.9500

Best Model: Gradient Boosting (Accuracy: 0.9500)
Model saved to models/phishing_model.pkl
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file:

```bash
# VirusTotal API Configuration
VIRUSTOTAL_API_KEY=your_api_key_here

# Server Configuration
PORT=5000
DEBUG=True

# Model Configuration
MODEL_PATH=models/phishing_model.pkl
VECTORIZER_PATH=models/vectorizer.pkl
```

### Custom Configuration

Edit `phishing_detector.py` to customize:
- Urgency keywords
- Sensitive information keywords
- Suspicious TLDs
- Legitimate domain patterns
- Risk scoring weights

---

## 📁 Project Structure

```
phishing-email-detector/
│
├── app.py                      # Flask web application
├── phishing_detector.py        # Core detection engine
├── train_model.py              # Model training utilities
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
├── README.md                   # This file
│
├── templates/
│   └── index.html             # Web interface HTML
│
├── static/
│   ├── css/
│   │   └── style.css          # Styling
│   └── js/
│       └── app.js             # Frontend JavaScript
│
├── datasets/
│   ├── README.md              # Dataset information
│   └── [your_datasets].csv    # Training data
│
├── models/
│   ├── phishing_model.pkl     # Trained model (generated)
│   └── vectorizer.pkl         # TF-IDF vectorizer (generated)
│
└── .env                       # Environment variables (create this)
```

---

## 📸 Screenshots

### Main Interface
Modern, dark-themed interface with intuitive input fields and clear call-to-action buttons.

### Risk Analysis Results
Comprehensive breakdown showing risk level, score, and detailed analysis of each phishing indicator.

### Detailed Findings
Expandable sections showing specific issues found in urgency tactics, sender validation, links, and more.

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Areas for Improvement

1. **Additional Detection Features**
   - Attachment analysis
   - Header analysis
   - Image-based phishing detection
   - Internationalization support

2. **ML Enhancements**
   - Deep learning models (LSTM, BERT)
   - Active learning pipeline
   - Model ensemble techniques

3. **UI/UX Improvements**
   - Browser extension
   - Email client plugins
   - Mobile app
   - Bulk analysis tool

4. **Integration**
   - Microsoft Outlook integration
   - Gmail API integration
   - Slack/Teams notifications

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🐛 Known Issues & Limitations

- VirusTotal API has rate limits (4 requests/minute for free tier)
- Some legitimate emails may be flagged (false positives)
- Non-English emails may have higher false positive rates
- Requires internet connection for URL reputation checking

---

## 🔒 Privacy & Security

- **No Data Storage**: Emails are analyzed in real-time and NOT stored
- **No Third-Party Sharing**: Your data stays on your machine (or your server)
- **Optional API**: VirusTotal integration is optional
- **Open Source**: Full code transparency for security audits

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Public Datasets**: Thanks to Nazario, APWG, and Kaggle for providing phishing datasets
- **Libraries**: scikit-learn, Flask, NLTK, and all other open-source dependencies
- **Community**: Security researchers and developers fighting phishing

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/phishing-email-detector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/phishing-email-detector/discussions)
- **Email**: your.email@example.com

---

## 🎉 Getting Started Checklist

- [ ] Clone the repository
- [ ] Install dependencies
- [ ] Download NLTK data
- [ ] Run the application
- [ ] Test with example email
- [ ] (Optional) Get VirusTotal API key
- [ ] (Optional) Train custom model with your datasets
- [ ] Analyze emails from your spam folder
- [ ] Share feedback and contribute!

---

<div align="center">

**Built with ❤️ for a safer internet**

⭐ Star this repo if you find it useful!

[Report Bug](https://github.com/yourusername/phishing-email-detector/issues) • [Request Feature](https://github.com/yourusername/phishing-email-detector/issues)

</div>
