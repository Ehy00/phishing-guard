"""
Phishing Email Detection Engine
Analyzes emails for phishing indicators and provides risk assessment
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
import requests
from langdetect import detect, LangDetectException
import nltk
from collections import Counter

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

try:
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('words', quiet=True)


class PhishingDetector:
    """Main phishing detection engine"""
    
    # Common phishing keywords that create urgency
    URGENCY_KEYWORDS = [
        'urgent', 'immediately', 'action required', 'verify now', 'suspended',
        'locked', 'expire', 'expires', 'expiring', 'limited time', 'act now',
        'confirm immediately', 'update required', 'security alert', 'unusual activity',
        'click here now', 'respond now', 'within 24 hours', 'within 48 hours',
        'your account will be closed', 'final notice', 'last warning', 'last chance'
    ]
    
    # Keywords requesting sensitive information
    SENSITIVE_INFO_KEYWORDS = [
        'social security', 'ssn', 'password', 'credit card', 'bank account',
        'pin', 'cvv', 'routing number', 'account number', 'date of birth',
        'mother\'s maiden name', 'verify your identity', 'confirm your password',
        'update payment', 'payment information', 'billing information',
        'tax id', 'driver\'s license', 'passport number'
    ]
    
    # Suspicious sender domains
    SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.click', '.link', '.download', '.gq', '.tk', '.ml']
    
    # Legitimate company domains (simplified list)
    LEGITIMATE_DOMAINS = {
        'paypal': ['paypal.com'],
        'amazon': ['amazon.com'],
        'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
        'apple': ['apple.com', 'icloud.com'],
        'google': ['google.com', 'gmail.com'],
        'bank': ['bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com']
    }
    
    def __init__(self, virustotal_api_key: str = None):
        """
        Initialize the phishing detector
        
        Args:
            virustotal_api_key: Optional VirusTotal API key for URL scanning
        """
        self.vt_api_key = virustotal_api_key
        
    def analyze_email(self, email_content: str, sender: str = None, subject: str = None) -> Dict:
        """
        Complete phishing analysis of an email
        
        Args:
            email_content: The email body/content
            sender: Email sender address
            subject: Email subject line
            
        Returns:
            Dictionary containing analysis results and risk score
        """
        results = {
            'urgency_tactics': self._check_urgency(email_content, subject),
            'sender_analysis': self._analyze_sender(sender) if sender else {},
            'sensitive_info_requests': self._check_sensitive_info(email_content),
            'link_analysis': self._analyze_links(email_content),
            'grammar_issues': self._check_grammar_issues(email_content),
            'risk_indicators': []
        }
        
        # Calculate overall risk score
        risk_score, risk_level = self._calculate_risk_score(results)
        results['risk_score'] = risk_score
        results['risk_level'] = risk_level
        results['explanation'] = self._generate_explanation(results)
        
        return results
    
    def _check_urgency(self, content: str, subject: str = None) -> Dict:
        """Check for urgency tactics"""
        content_lower = content.lower()
        subject_lower = subject.lower() if subject else ""
        
        found_urgency = []
        for keyword in self.URGENCY_KEYWORDS:
            if keyword in content_lower or keyword in subject_lower:
                found_urgency.append(keyword)
        
        # Check for excessive exclamation marks
        exclamation_count = content.count('!') + (subject.count('!') if subject else 0)
        
        # Check for ALL CAPS usage (more than 20% of content)
        caps_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
        
        return {
            'detected': len(found_urgency) > 0 or exclamation_count > 3 or caps_ratio > 0.2,
            'urgency_keywords': found_urgency,
            'excessive_exclamation': exclamation_count > 3,
            'excessive_caps': caps_ratio > 0.2,
            'severity': 'high' if len(found_urgency) >= 3 else 'medium' if len(found_urgency) > 0 else 'low'
        }
    
    def _analyze_sender(self, sender: str) -> Dict:
        """Analyze sender email address for suspicious patterns"""
        if not sender:
            return {'detected': False}
        
        sender_lower = sender.lower()
        issues = []
        
        # Extract domain
        try:
            if '@' in sender:
                local_part, domain = sender.split('@', 1)
            else:
                return {'detected': True, 'issues': ['Invalid email format'], 'severity': 'high'}
        except:
            return {'detected': True, 'issues': ['Invalid email format'], 'severity': 'high'}
        
        # Check for suspicious TLDs
        extracted = tldextract.extract(domain)
        tld = '.' + extracted.suffix if extracted.suffix else ''
        if tld in self.SUSPICIOUS_TLDS:
            issues.append(f'Suspicious TLD: {tld}')
        
        # Check for domain spoofing (e.g., paypa1.com instead of paypal.com)
        for company, legitimate_domains in self.LEGITIMATE_DOMAINS.items():
            if company in domain and not any(legit in domain for legit in legitimate_domains):
                issues.append(f'Possible {company} domain spoofing')
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            issues.append('Excessive subdomains (possible obfuscation)')
        
        # Check for numbers in domain (often suspicious)
        if re.search(r'\d{3,}', domain):
            issues.append('Domain contains multiple numbers')
        
        # Check for misspellings of common services
        common_misspellings = ['g00gle', 'micros0ft', 'amazn', 'paypa1']
        if any(misspell in domain for misspell in common_misspellings):
            issues.append('Likely domain name misspelling')
        
        return {
            'detected': len(issues) > 0,
            'issues': issues,
            'domain': domain,
            'severity': 'high' if len(issues) >= 2 else 'medium' if len(issues) == 1 else 'low'
        }
    
    def _check_sensitive_info(self, content: str) -> Dict:
        """Check for requests for sensitive information"""
        content_lower = content.lower()
        found_requests = []
        
        for keyword in self.SENSITIVE_INFO_KEYWORDS:
            if keyword in content_lower:
                found_requests.append(keyword)
        
        # Check for form-like patterns
        has_form_fields = bool(re.search(r'(enter|provide|submit|input|type).{0,30}(password|card|ssn|pin)', content_lower))
        
        return {
            'detected': len(found_requests) > 0 or has_form_fields,
            'requested_info': found_requests,
            'has_form_fields': has_form_fields,
            'severity': 'high' if len(found_requests) >= 2 else 'medium' if len(found_requests) > 0 else 'low'
        }
    
    def _analyze_links(self, content: str) -> Dict:
        """Analyze links in the email"""
        # Extract URLs from text
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        # Also check for HTML links
        soup = BeautifulSoup(content, 'html.parser')
        html_links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        all_urls = list(set(urls + html_links))
        issues = []
        suspicious_urls = []
        
        for url in all_urls:
            url_issues = self._check_url_suspicious(url)
            if url_issues:
                suspicious_urls.append({'url': url, 'issues': url_issues})
                issues.extend(url_issues)
        
        # Check for link text mismatch (display text different from actual URL)
        link_mismatches = []
        for a in soup.find_all('a', href=True):
            text = a.get_text().strip()
            href = a.get('href')
            if text.startswith('http') and href.startswith('http') and text != href:
                link_mismatches.append({'display': text, 'actual': href})
        
        return {
            'detected': len(suspicious_urls) > 0 or len(link_mismatches) > 0,
            'total_links': len(all_urls),
            'suspicious_urls': suspicious_urls,
            'link_mismatches': link_mismatches,
            'severity': 'high' if len(suspicious_urls) >= 2 else 'medium' if len(suspicious_urls) > 0 else 'low'
        }
    
    def _check_url_suspicious(self, url: str) -> List[str]:
        """Check if a URL has suspicious characteristics"""
        issues = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check for IP address instead of domain
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                issues.append('Uses IP address instead of domain name')
            
            # Check for suspicious TLDs
            extracted = tldextract.extract(domain)
            tld = '.' + extracted.suffix if extracted.suffix else ''
            if tld in self.SUSPICIOUS_TLDS:
                issues.append(f'Suspicious TLD: {tld}')
            
            # Check for @ symbol in URL (authentication bypass trick)
            if '@' in url:
                issues.append('Contains @ symbol (possible redirect trick)')
            
            # Check for excessive length
            if len(url) > 200:
                issues.append('Unusually long URL')
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
            if any(shortener in domain for shortener in shorteners):
                issues.append('Uses URL shortener (hides destination)')
            
            # Check for too many subdomains
            if domain.count('.') > 3:
                issues.append('Excessive subdomains')
                
        except Exception as e:
            issues.append('Malformed URL')
        
        return issues
    
    def check_url_reputation(self, url: str) -> Dict:
        """
        Check URL reputation using VirusTotal API
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with reputation results
        """
        if not self.vt_api_key:
            return {'available': False, 'message': 'API key not configured'}
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'available': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'is_threat': stats.get('malicious', 0) + stats.get('suspicious', 0) > 0
                }
            else:
                return {'available': False, 'message': 'URL not found in database'}
                
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def _check_grammar_issues(self, content: str) -> Dict:
        """Check for grammar and spelling issues"""
        issues = []
        
        # Remove HTML tags for text analysis
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text()
        
        # Check for common grammar issues
        # Multiple spaces
        if re.search(r'\s{3,}', text):
            issues.append('Excessive whitespace found')
        
        # Missing spaces after punctuation
        if re.search(r'[.,!?][A-Z]', text):
            issues.append('Missing spaces after punctuation')
        
        # Inconsistent capitalization
        sentences = re.split(r'[.!?]\s+', text)
        lowercase_starts = sum(1 for s in sentences if s and s[0].islower())
        if lowercase_starts > len(sentences) * 0.3:  # More than 30% start with lowercase
            issues.append('Inconsistent capitalization')
        
        # Check for repeated words
        words = text.lower().split()
        for i in range(len(words) - 1):
            if words[i] == words[i + 1] and len(words[i]) > 3:
                issues.append(f'Repeated word: "{words[i]}"')
                break
        
        # Check for unusual character combinations
        if re.search(r'[a-z]{15,}', text):
            issues.append('Unusually long words without spaces')
        
        # Try to detect language
        try:
            lang = detect(text) if text.strip() else 'unknown'
            if lang not in ['en', 'unknown']:
                # Check if email claims to be from English-speaking company
                english_companies = ['paypal', 'amazon', 'microsoft', 'apple', 'bank']
                if any(company in content.lower() for company in english_companies):
                    issues.append(f'Language mismatch (detected: {lang}, expected: English)')
        except LangDetectException:
            pass
        
        return {
            'detected': len(issues) > 0,
            'issues': issues,
            'severity': 'high' if len(issues) >= 3 else 'medium' if len(issues) >= 1 else 'low'
        }
    
    def _calculate_risk_score(self, results: Dict) -> Tuple[int, str]:
        """
        Calculate overall risk score (0-100) and risk level
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            Tuple of (risk_score, risk_level)
        """
        score = 0
        
        # Urgency tactics (up to 20 points)
        if results['urgency_tactics']['detected']:
            severity = results['urgency_tactics']['severity']
            if severity == 'high':
                score += 20
            elif severity == 'medium':
                score += 12
            else:
                score += 5
        
        # Sender analysis (up to 25 points)
        if results['sender_analysis'].get('detected'):
            severity = results['sender_analysis']['severity']
            if severity == 'high':
                score += 25
            elif severity == 'medium':
                score += 15
            else:
                score += 8
        
        # Sensitive info requests (up to 25 points)
        if results['sensitive_info_requests']['detected']:
            severity = results['sensitive_info_requests']['severity']
            if severity == 'high':
                score += 25
            elif severity == 'medium':
                score += 15
            else:
                score += 8
        
        # Link analysis (up to 20 points)
        if results['link_analysis']['detected']:
            severity = results['link_analysis']['severity']
            if severity == 'high':
                score += 20
            elif severity == 'medium':
                score += 12
            else:
                score += 6
        
        # Grammar issues (up to 10 points)
        if results['grammar_issues']['detected']:
            severity = results['grammar_issues']['severity']
            if severity == 'high':
                score += 10
            elif severity == 'medium':
                score += 6
            else:
                score += 3
        
        # Determine risk level
        if score >= 60:
            risk_level = "High"
        elif score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return score, risk_level
    
    def _generate_explanation(self, results: Dict) -> str:
        """Generate human-readable explanation of the analysis"""
        explanations = []
        
        if results['urgency_tactics']['detected']:
            urgency = results['urgency_tactics']
            explanations.append(
                f"⚠️ **Urgency Tactics Detected**: Found {len(urgency['urgency_keywords'])} "
                f"urgency-creating phrases that pressure recipients to act quickly."
            )
        
        if results['sender_analysis'].get('detected'):
            sender = results['sender_analysis']
            explanations.append(
                f"🚨 **Suspicious Sender**: {len(sender['issues'])} issue(s) detected - "
                f"{', '.join(sender['issues'][:2])}"
            )
        
        if results['sensitive_info_requests']['detected']:
            sensitive = results['sensitive_info_requests']
            explanations.append(
                f"🔐 **Requests Sensitive Information**: Asks for {len(sensitive['requested_info'])} "
                f"type(s) of sensitive data. Legitimate companies rarely request this via email."
            )
        
        if results['link_analysis']['detected']:
            links = results['link_analysis']
            explanations.append(
                f"🔗 **Suspicious Links**: {len(links['suspicious_urls'])} suspicious URL(s) detected. "
                f"These may lead to malicious websites."
            )
        
        if results['grammar_issues']['detected']:
            grammar = results['grammar_issues']
            explanations.append(
                f"📝 **Grammar Issues**: {len(grammar['issues'])} language/formatting issue(s) found. "
                f"Professional emails are typically well-written."
            )
        
        if not explanations:
            explanations.append("✅ No major phishing indicators detected in this email.")
        
        return "\n\n".join(explanations)


if __name__ == "__main__":
    # Example usage
    detector = PhishingDetector()
    
    sample_email = """
    URGENT ACTION REQUIRED!
    
    Dear Customer,
    
    Your PayPal account has been suspended due to unusual activity. 
    You must verify your identity immediately within 24 hours or your account will be permanently closed.
    
    Click here to verify: http://paypa1-secure.xyz/verify
    
    Please provide your:
    - Full name
    - Credit card number
    - Password
    - Social Security Number
    
    Best regards,
    PayPal Security Team
    """
    
    result = detector.analyze_email(
        email_content=sample_email,
        sender="security@paypa1-alert.xyz",
        subject="URGENT: Verify Your PayPal Account NOW!"
    )
    
    print(f"Risk Level: {result['risk_level']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"\n{result['explanation']}")
