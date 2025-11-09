# 🚀 Deployment Guide

This guide covers various deployment options for the Phishing Email Detector.

## 📋 Table of Contents

- [Local Development](#local-development)
- [Production Deployment](#production-deployment)
- [Docker Deployment](#docker-deployment)
- [Cloud Platforms](#cloud-platforms)
- [Security Considerations](#security-considerations)

---

## 🏠 Local Development

### Quick Start

```bash
# Clone and setup
git clone https://github.com/yourusername/phishing-email-detector.git
cd phishing-email-detector
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run development server
python app.py
```

Access at: `http://localhost:5000`

---

## 🌐 Production Deployment

### Using Gunicorn (Linux/Mac)

1. **Install Gunicorn**:
   ```bash
   pip install gunicorn
   ```

2. **Run with Gunicorn**:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

3. **With systemd service** (`/etc/systemd/system/phishing-detector.service`):
   ```ini
   [Unit]
   Description=Phishing Email Detector
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/var/www/phishing-detector
   Environment="PATH=/var/www/phishing-detector/venv/bin"
   ExecStart=/var/www/phishing-detector/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app

   [Install]
   WantedBy=multi-user.target
   ```

4. **Start service**:
   ```bash
   sudo systemctl start phishing-detector
   sudo systemctl enable phishing-detector
   ```

### Using Nginx Reverse Proxy

1. **Install Nginx**:
   ```bash
   sudo apt install nginx
   ```

2. **Configure** (`/etc/nginx/sites-available/phishing-detector`):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }

       location /static {
           alias /var/www/phishing-detector/static;
           expires 30d;
       }
   }
   ```

3. **Enable and restart**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/phishing-detector /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

### SSL/HTTPS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## 🐳 Docker Deployment

### 1. Create Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data
RUN python -c "import nltk; nltk.download('punkt'); nltk.download('words')"

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p models datasets

# Expose port
EXPOSE 5000

# Run application
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

### 2. Create docker-compose.yml

```yaml
version: '3.8'

services:
  phishing-detector:
    build: .
    ports:
      - "5000:5000"
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - DEBUG=False
    volumes:
      - ./models:/app/models
      - ./datasets:/app/datasets
    restart: unless-stopped
```

### 3. Build and Run

```bash
# Build image
docker-compose build

# Run container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop container
docker-compose down
```

---

## ☁️ Cloud Platforms

### Heroku

1. **Create Procfile**:
   ```
   web: gunicorn app:app
   ```

2. **Create runtime.txt**:
   ```
   python-3.9.16
   ```

3. **Deploy**:
   ```bash
   heroku create phishing-detector-app
   heroku config:set VIRUSTOTAL_API_KEY=your_key_here
   git push heroku main
   ```

### AWS EC2

1. **Launch EC2 instance** (Ubuntu 22.04)

2. **Connect and setup**:
   ```bash
   ssh -i your-key.pem ubuntu@your-ec2-ip
   
   # Update system
   sudo apt update && sudo apt upgrade -y
   
   # Install Python and dependencies
   sudo apt install python3-pip python3-venv nginx -y
   
   # Clone repository
   git clone https://github.com/yourusername/phishing-detector.git
   cd phishing-detector
   
   # Setup virtual environment
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure Nginx** (see above)

4. **Setup systemd service** (see above)

### Google Cloud Platform

1. **Create app.yaml**:
   ```yaml
   runtime: python39
   entrypoint: gunicorn -b :$PORT app:app

   env_variables:
     VIRUSTOTAL_API_KEY: "your_key_here"

   automatic_scaling:
     min_instances: 1
     max_instances: 5
   ```

2. **Deploy**:
   ```bash
   gcloud app deploy
   ```

### Azure Web App

1. **Create Web App** in Azure Portal

2. **Configure deployment**:
   ```bash
   az webapp up --name phishing-detector --resource-group myResourceGroup
   ```

3. **Set environment variables**:
   ```bash
   az webapp config appsettings set --name phishing-detector \
     --resource-group myResourceGroup \
     --settings VIRUSTOTAL_API_KEY=your_key_here
   ```

### DigitalOcean App Platform

1. **Create app.yaml**:
   ```yaml
   name: phishing-detector
   services:
   - name: web
     github:
       repo: yourusername/phishing-detector
       branch: main
     build_command: pip install -r requirements.txt
     run_command: gunicorn --workers 2 --bind 0.0.0.0:8080 app:app
     envs:
     - key: VIRUSTOTAL_API_KEY
       value: your_key_here
   ```

2. **Deploy via** DigitalOcean dashboard or CLI

---

## 🔒 Security Considerations

### 1. Environment Variables
```bash
# Never commit .env files
# Use secure key management services
export VIRUSTOTAL_API_KEY="your_secret_key"
```

### 2. HTTPS
- Always use HTTPS in production
- Use Let's Encrypt for free SSL certificates
- Redirect HTTP to HTTPS

### 3. Rate Limiting
Add rate limiting to prevent abuse:
```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_email():
    # ...
```

### 4. Input Validation
- Sanitize all user inputs
- Limit upload sizes
- Validate email formats

### 5. Firewall Rules
```bash
# Allow only necessary ports
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

### 6. Regular Updates
```bash
# Keep system and packages updated
sudo apt update && sudo apt upgrade -y
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```

### 7. Monitoring
- Set up logging
- Monitor error rates
- Track API usage
- Use tools like:
  - Sentry for error tracking
  - Prometheus for metrics
  - ELK stack for log analysis

---

## 📊 Performance Optimization

### 1. Caching
Implement caching for repeated analyses:
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def analyze_domain(domain):
    # Cached domain analysis
    pass
```

### 2. Database
For production, consider storing results:
- PostgreSQL for relational data
- Redis for caching
- MongoDB for document storage

### 3. Load Balancing
For high traffic, use:
- Multiple Gunicorn workers
- Nginx load balancing
- Cloud load balancers

### 4. CDN
Use CDN for static assets:
- CloudFlare
- AWS CloudFront
- Azure CDN

---

## 🔍 Monitoring & Maintenance

### Health Checks
```bash
# Check if application is running
curl http://localhost:5000/api/health

# Check system resources
htop
df -h
```

### Logs
```bash
# View application logs
tail -f /var/log/phishing-detector/app.log

# View Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# View systemd logs
sudo journalctl -u phishing-detector -f
```

### Backup
```bash
# Backup models and datasets
tar -czf backup-$(date +%Y%m%d).tar.gz models/ datasets/

# Automated backup with cron
0 2 * * * /path/to/backup-script.sh
```

---

## 🆘 Troubleshooting

### Application won't start
```bash
# Check logs
python app.py  # Run in foreground to see errors
tail -f app.log

# Check dependencies
pip list
pip check
```

### Port already in use
```bash
# Find process using port 5000
sudo lsof -i :5000

# Kill process
kill -9 <PID>
```

### Permission issues
```bash
# Fix ownership
sudo chown -R www-data:www-data /var/www/phishing-detector

# Fix permissions
chmod -R 755 /var/www/phishing-detector
```

---

## 📞 Support

For deployment issues:
- Check logs first
- Search existing GitHub issues
- Open a new issue with:
  - Deployment environment
  - Error messages
  - Steps to reproduce

---

**Happy Deploying! 🚀**
