// Phishing Detector Frontend Application

const API_BASE_URL = window.location.origin;

// DOM Elements
const analysisForm = document.getElementById('analysisForm');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const exampleBtn = document.getElementById('exampleBtn');
const resultsSection = document.getElementById('resultsSection');
const loadingOverlay = document.getElementById('loadingOverlay');
const riskScoreContainer = document.getElementById('riskScoreContainer');
const analysisDetails = document.getElementById('analysisDetails');

// Event Listeners
analysisForm.addEventListener('submit', handleFormSubmit);
clearBtn.addEventListener('click', clearForm);
exampleBtn.addEventListener('click', loadExampleEmail);

// Form Submit Handler
async function handleFormSubmit(e) {
    e.preventDefault();
    
    const sender = document.getElementById('sender').value.trim();
    const subject = document.getElementById('subject').value.trim();
    const emailContent = document.getElementById('emailContent').value.trim();
    
    if (!emailContent) {
        showNotification('Please enter email content', 'error');
        return;
    }
    
    // Show loading
    showLoading();
    hideResults();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email_content: emailContent,
                sender: sender,
                subject: subject
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Analysis failed');
        }
        
        const results = await response.json();
        displayResults(results);
        
    } catch (error) {
        console.error('Analysis error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

// Display Results
function displayResults(results) {
    // Display Risk Score
    displayRiskScore(results);
    
    // Display Detailed Analysis
    displayDetailedAnalysis(results);
    
    // Show results section
    showResults();
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Display Risk Score
function displayRiskScore(results) {
    const riskLevel = results.risk_level || 'Unknown';
    const riskScore = results.risk_score || 0;
    const explanation = results.explanation || '';
    
    const riskClass = `risk-${riskLevel.toLowerCase()}`;
    const emoji = getRiskEmoji(riskLevel);
    
    riskScoreContainer.innerHTML = `
        <div class="risk-badge ${riskClass}">
            ${emoji} ${riskLevel} Risk
        </div>
        <div class="risk-score">${riskScore}/100</div>
        <p style="color: var(--text-secondary); font-size: 1.1rem; margin-top: 1rem;">
            ${getRiskMessage(riskLevel)}
        </p>
        ${explanation ? `
            <div class="risk-explanation">
                ${formatExplanation(explanation)}
            </div>
        ` : ''}
    `;
}

// Display Detailed Analysis
function displayDetailedAnalysis(results) {
    let html = '<div class="analysis-details-container">';
    
    // Urgency Tactics
    html += createAnalysisSection(
        '⚡ Urgency Tactics',
        results.urgency_tactics,
        formatUrgencyDetails(results.urgency_tactics)
    );
    
    // Sender Analysis
    if (results.sender_analysis && Object.keys(results.sender_analysis).length > 0) {
        html += createAnalysisSection(
            '📧 Sender Analysis',
            results.sender_analysis,
            formatSenderDetails(results.sender_analysis)
        );
    }
    
    // Sensitive Information Requests
    html += createAnalysisSection(
        '🔐 Sensitive Information Requests',
        results.sensitive_info_requests,
        formatSensitiveInfoDetails(results.sensitive_info_requests)
    );
    
    // Link Analysis
    html += createAnalysisSection(
        '🔗 Link Analysis',
        results.link_analysis,
        formatLinkDetails(results.link_analysis)
    );
    
    // Grammar Issues
    html += createAnalysisSection(
        '📝 Grammar & Language',
        results.grammar_issues,
        formatGrammarDetails(results.grammar_issues)
    );
    
    html += '</div>';
    analysisDetails.innerHTML = html;
}

// Create Analysis Section
function createAnalysisSection(title, data, detailsHtml) {
    const isDetected = data && data.detected;
    const statusClass = isDetected ? 'status-detected' : 'status-clean';
    const statusText = isDetected ? 'Issues Found' : 'Clean';
    
    return `
        <div class="analysis-section">
            <h3>
                ${title}
                <span class="status-badge ${statusClass}">${statusText}</span>
            </h3>
            ${detailsHtml}
        </div>
    `;
}

// Format Urgency Details
function formatUrgencyDetails(urgency) {
    if (!urgency || !urgency.detected) {
        return '<p style="color: var(--success-color);">✓ No urgency tactics detected</p>';
    }
    
    let html = '<ul class="detail-list">';
    
    if (urgency.urgency_keywords && urgency.urgency_keywords.length > 0) {
        html += `<li><strong>Urgency keywords found:</strong> ${urgency.urgency_keywords.join(', ')}</li>`;
    }
    
    if (urgency.excessive_exclamation) {
        html += '<li><strong>Excessive exclamation marks</strong> detected (pressure tactic)</li>';
    }
    
    if (urgency.excessive_caps) {
        html += '<li><strong>Excessive capital letters</strong> used (shouting)</li>';
    }
    
    html += '</ul>';
    html += `<div class="info-box">
        <strong>Why this matters:</strong> Phishing emails often create artificial urgency to pressure 
        recipients into acting without thinking. Legitimate companies typically don't rush you.
    </div>`;
    
    return html;
}

// Format Sender Details
function formatSenderDetails(sender) {
    if (!sender || !sender.detected) {
        return '<p style="color: var(--success-color);">✓ Sender appears legitimate</p>';
    }
    
    let html = '<ul class="detail-list">';
    
    if (sender.domain) {
        html += `<li><strong>Sender domain:</strong> ${sender.domain}</li>`;
    }
    
    if (sender.issues && sender.issues.length > 0) {
        sender.issues.forEach(issue => {
            html += `<li>${issue}</li>`;
        });
    }
    
    html += '</ul>';
    html += `<div class="info-box">
        <strong>Why this matters:</strong> Attackers often use domains that look similar to legitimate 
        companies (typosquatting) or suspicious domain extensions to deceive recipients.
    </div>`;
    
    return html;
}

// Format Sensitive Info Details
function formatSensitiveInfoDetails(sensitiveInfo) {
    if (!sensitiveInfo || !sensitiveInfo.detected) {
        return '<p style="color: var(--success-color);">✓ No requests for sensitive information</p>';
    }
    
    let html = '<ul class="detail-list">';
    
    if (sensitiveInfo.requested_info && sensitiveInfo.requested_info.length > 0) {
        html += `<li><strong>Requests for:</strong> ${sensitiveInfo.requested_info.join(', ')}</li>`;
    }
    
    if (sensitiveInfo.has_form_fields) {
        html += '<li><strong>Contains form-like input requests</strong></li>';
    }
    
    html += '</ul>';
    html += `<div class="info-box" style="border-color: var(--danger-color); background: rgba(239, 68, 68, 0.1);">
        <strong>⚠️ Critical Warning:</strong> Legitimate companies will NEVER ask for passwords, 
        credit card details, SSN, or other sensitive information via email. This is a major red flag!
    </div>`;
    
    return html;
}

// Format Link Details
function formatLinkDetails(links) {
    if (!links || !links.detected) {
        return '<p style="color: var(--success-color);">✓ No suspicious links detected</p>';
    }
    
    let html = '<ul class="detail-list">';
    
    if (links.total_links !== undefined) {
        html += `<li><strong>Total links found:</strong> ${links.total_links}</li>`;
    }
    
    if (links.suspicious_urls && links.suspicious_urls.length > 0) {
        html += '<li><strong>Suspicious URLs:</strong></li>';
        html += '<ul style="margin-left: 2rem; margin-top: 0.5rem;">';
        links.suspicious_urls.forEach(urlData => {
            html += `<li style="word-break: break-all; font-family: monospace; font-size: 0.9rem;">
                <strong>${urlData.url}</strong><br>
                <span style="color: var(--danger-color);">Issues: ${urlData.issues.join(', ')}</span>
            </li>`;
        });
        html += '</ul>';
    }
    
    if (links.link_mismatches && links.link_mismatches.length > 0) {
        html += '<li><strong>⚠️ Link text mismatches detected:</strong></li>';
        html += '<ul style="margin-left: 2rem; margin-top: 0.5rem;">';
        links.link_mismatches.forEach(mismatch => {
            html += `<li style="font-family: monospace; font-size: 0.9rem;">
                Display: <span style="color: var(--text-primary);">${mismatch.display}</span><br>
                Actual: <span style="color: var(--danger-color);">${mismatch.actual}</span>
            </li>`;
        });
        html += '</ul>';
    }
    
    html += '</ul>';
    html += `<div class="info-box">
        <strong>Why this matters:</strong> Phishers use deceptive links to trick you into visiting 
        malicious websites. Always hover over links to see the real destination before clicking.
    </div>`;
    
    return html;
}

// Format Grammar Details
function formatGrammarDetails(grammar) {
    if (!grammar || !grammar.detected) {
        return '<p style="color: var(--success-color);">✓ No significant grammar or language issues</p>';
    }
    
    let html = '<ul class="detail-list">';
    
    if (grammar.issues && grammar.issues.length > 0) {
        grammar.issues.forEach(issue => {
            html += `<li>${issue}</li>`;
        });
    }
    
    html += '</ul>';
    html += `<div class="info-box">
        <strong>Why this matters:</strong> Professional companies have editors and quality control. 
        Poor grammar, spelling errors, and formatting issues are common in phishing emails, especially 
        those translated from other languages.
    </div>`;
    
    return html;
}

// Helper Functions
function getRiskEmoji(riskLevel) {
    const emojis = {
        'low': '✅',
        'medium': '⚠️',
        'high': '🚨'
    };
    return emojis[riskLevel.toLowerCase()] || '❓';
}

function getRiskMessage(riskLevel) {
    const messages = {
        'low': 'This email appears relatively safe, but always remain vigilant.',
        'medium': 'This email shows some suspicious characteristics. Exercise caution.',
        'high': 'This email exhibits multiple phishing indicators. Do NOT interact with it!'
    };
    return messages[riskLevel.toLowerCase()] || 'Unable to determine risk level.';
}

function formatExplanation(explanation) {
    // Convert markdown-like formatting to HTML
    return explanation
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/⚠️|🚨|🔐|🔗|📝|✅/g, match => `<span style="font-size: 1.2em;">${match}</span>`)
        .split('\n\n')
        .map(para => `<p style="margin-bottom: 1rem;">${para}</p>`)
        .join('');
}

// Load Example Email
function loadExampleEmail() {
    const exampleEmail = {
        sender: 'security@paypa1-verify.xyz',
        subject: 'URGENT: Verify Your Account NOW!',
        content: `URGENT ACTION REQUIRED!

Dear Valued Customer,

Your PayPal account has been temporarily suspended due to unusual activity detected on your account. 
You must verify your identity IMMEDIATELY within 24 hours or your account will be permanently closed 
and all funds will be frozen.

Click here to verify your account now: http://paypa1-secure.xyz/verify-account-2024

To restore full access, please provide the following information:
- Your full name and date of birth
- Credit card number and CVV code
- Social Security Number
- Current password and mother's maiden name

FAILURE TO RESPOND WITHIN 24 HOURS WILL RESULT IN PERMANENT ACCOUNT CLOSURE!!!

Thank you for your immediate attention to this matter.

Best Regards,
PayPal Security Team

Note: This is an automated message, please do not reply to this email.`
    };
    
    document.getElementById('sender').value = exampleEmail.sender;
    document.getElementById('subject').value = exampleEmail.subject;
    document.getElementById('emailContent').value = exampleEmail.content;
    
    showNotification('Example phishing email loaded', 'success');
}

// Clear Form
function clearForm() {
    analysisForm.reset();
    hideResults();
    showNotification('Form cleared', 'info');
}

// Show/Hide Functions
function showLoading() {
    loadingOverlay.style.display = 'flex';
    analyzeBtn.disabled = true;
}

function hideLoading() {
    loadingOverlay.style.display = 'none';
    analyzeBtn.disabled = false;
}

function showResults() {
    resultsSection.style.display = 'block';
}

function hideResults() {
    resultsSection.style.display = 'none';
}

// Notification System
function showNotification(message, type = 'info') {
    const colors = {
        success: '#22c55e',
        error: '#ef4444',
        info: '#6366f1',
        warning: '#f59e0b'
    };
    
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type]};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// About Modal
function showAbout() {
    alert(`Phishing Email Detector v1.0

An advanced AI-powered tool for detecting phishing attempts in emails.

Features:
- Urgency tactic detection
- Sender domain analysis
- Sensitive information request detection
- Suspicious link analysis
- Grammar and language checking
- Risk scoring algorithm

Built with Python (Flask) and modern web technologies.`);
}

// Privacy Modal
function showPrivacy() {
    alert(`Privacy Policy

Your privacy is important to us:

✓ Emails are analyzed in real-time and NOT stored
✓ No data is shared with third parties
✓ Analysis is performed locally on our servers
✓ Optional: VirusTotal API for URL reputation checking

For local deployment, all analysis happens on your machine.`);
}

// Initialize
console.log('Phishing Detector initialized');
