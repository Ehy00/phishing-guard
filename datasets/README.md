# Phishing Email Datasets

This directory contains datasets for training the phishing detection model.

## Recommended Public Datasets

### 1. Nazario Phishing Corpus
- **Source**: http://monkey.org/~jose/phishing/
- **Description**: One of the oldest and most comprehensive phishing email collections
- **Format**: Individual email files
- **How to use**: Download and convert to CSV format

### 2. APWG (Anti-Phishing Working Group)
- **Source**: https://apwg.org/
- **Description**: Regular phishing activity reports and datasets
- **How to use**: Contact APWG for research access

### 3. Kaggle Phishing Email Datasets
- **Phishing Email Dataset**: https://www.kaggle.com/datasets/subhajournal/phishingemails
- **Email Classification**: https://www.kaggle.com/datasets/venky73/spam-mails-dataset
- **Format**: CSV files with email text and labels

### 4. Enron Email Dataset (Legitimate Emails)
- **Source**: https://www.cs.cmu.edu/~enron/
- **Description**: Large corpus of legitimate business emails
- **Use**: As negative examples (non-phishing)

## Dataset Format

Your CSV files should have these columns:
- `text` or `email` or `body`: The email content
- `is_phishing` or `label`: 1 for phishing, 0 for legitimate

Example CSV structure:
```csv
text,is_phishing
"URGENT: Your account will be suspended...",1
"Hi team, meeting at 2pm tomorrow...",0
```

## Quick Start

1. Download datasets from the sources above
2. Place CSV files in this directory
3. Run the training script:
   ```bash
   python train_model.py
   ```

## Creating Your Own Dataset

You can also create your own dataset using real examples from your spam folder:

1. Export spam emails (Forward as attachments or copy text)
2. Create a CSV file with the format above
3. Include both phishing and legitimate examples
4. Aim for balanced classes (50% phishing, 50% legitimate)

## Dataset Statistics

After loading datasets, the training script will display:
- Total number of samples
- Number of phishing emails
- Number of legitimate emails
- Class distribution

## Privacy Note

⚠️ **Important**: Never include emails containing:
- Real personal information (names, addresses, SSN)
- Real credentials or passwords
- Confidential business information

Sanitize or use publicly available datasets only.
