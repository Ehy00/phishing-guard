# ⚡ Quick Start Guide

Get the Phishing Email Detector up and running in 5 minutes!

## 🚀 Fast Track Installation

### Step 1: Prerequisites (1 minute)

Make sure you have:
- ✅ Python 3.8 or higher
- ✅ pip (Python package manager)
- ✅ Git

Check your Python version:
```bash
python --version
```

### Step 2: Clone & Setup (2 minutes)

```bash
# Clone the repository
git clone https://github.com/yourusername/phishing-email-detector.git
cd phishing-email-detector

# Create virtual environment
python -m venv venv

# Activate it
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download required NLTK data
python -c "import nltk; nltk.download('punkt'); nltk.download('words')"
```

### Step 3: Verify Installation (30 seconds)

```bash
python test_installation.py
```

If all tests pass ✓, continue to Step 4!

### Step 4: Run the Application (30 seconds)

```bash
python app.py
```

### Step 5: Open in Browser (30 seconds)

Open your web browser and go to:
```
http://localhost:5000
```

## 🎯 First Test

1. Click the **"Load Example"** button
2. Click **"Analyze Email"**
3. See the magic happen! 🎩✨

## 🔧 Optional: Add VirusTotal API

For URL reputation checking:

1. Get a free API key: https://www.virustotal.com/gui/join-us
2. Create `.env` file:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` and add your key:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

## 📝 Try Your Own Emails

1. Copy an email from your spam folder
2. Paste it into the "Email Content" field
3. (Optional) Add sender and subject
4. Click "Analyze Email"
5. Review the risk assessment!

## 🎓 Next Steps

- 📖 Read the full [README.md](README.md) for detailed features
- 🤖 Train your own model with [train_model.py](train_model.py)
- 🚀 Deploy to production using [DEPLOYMENT.md](DEPLOYMENT.md)
- 🤝 Contribute via [CONTRIBUTING.md](CONTRIBUTING.md)

## ❓ Troubleshooting

### Command not found: python

Try `python3` instead:
```bash
python3 --version
python3 -m venv venv
```

### ModuleNotFoundError

Make sure virtual environment is activated and dependencies installed:
```bash
source venv/bin/activate  # Activate venv
pip install -r requirements.txt
```

### Port 5000 already in use

Either:
- Stop the other process using port 5000
- Use a different port:
  ```bash
  PORT=8000 python app.py
  ```

### NLTK data not found

Download it manually:
```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('words')"
```

## 🆘 Still Having Issues?

- Run the test script: `python test_installation.py`
- Check [GitHub Issues](https://github.com/yourusername/phishing-email-detector/issues)
- Review detailed [README.md](README.md)

## 🎉 Success!

You're now ready to detect phishing emails!

**Happy phishing hunting! 🎣🛡️**

---

<div align="center">

[📖 Full Documentation](README.md) | [🐛 Report Bug](https://github.com/yourusername/phishing-email-detector/issues) | [💡 Request Feature](https://github.com/yourusername/phishing-email-detector/issues)

</div>
