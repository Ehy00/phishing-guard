"""
Training utilities for phishing detection model
Uses public datasets: Nazario, APWG, and Kaggle phishing email datasets
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import os
import re
from typing import Dict, Tuple
import nltk
from phishing_detector import PhishingDetector


class PhishingModelTrainer:
    """Train and evaluate phishing detection models"""
    
    def __init__(self, dataset_path: str = 'datasets/'):
        """
        Initialize the trainer
        
        Args:
            dataset_path: Path to dataset directory
        """
        self.dataset_path = dataset_path
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words='english'
        )
        self.model = None
        self.feature_detector = PhishingDetector()
        
    def load_datasets(self) -> pd.DataFrame:
        """
        Load and combine multiple phishing datasets
        
        Returns:
            Combined DataFrame with 'text' and 'is_phishing' columns
        """
        print("Loading datasets...")
        
        datasets = []
        
        # Try to load CSV files from datasets directory
        dataset_files = [
            'phishing_emails.csv',
            'nazario_phishing.csv',
            'apwg_phishing.csv',
            'kaggle_phishing.csv'
        ]
        
        for filename in dataset_files:
            filepath = os.path.join(self.dataset_path, filename)
            if os.path.exists(filepath):
                try:
                    df = pd.read_csv(filepath)
                    print(f"Loaded {filename}: {len(df)} samples")
                    datasets.append(df)
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
        
        if not datasets:
            print("No dataset files found. Generating sample dataset...")
            return self._generate_sample_dataset()
        
        # Combine all datasets
        combined_df = pd.concat(datasets, ignore_index=True)
        
        # Standardize column names
        combined_df = self._standardize_columns(combined_df)
        
        print(f"Total samples loaded: {len(combined_df)}")
        print(f"Phishing emails: {combined_df['is_phishing'].sum()}")
        print(f"Legitimate emails: {len(combined_df) - combined_df['is_phishing'].sum()}")
        
        return combined_df
    
    def _standardize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names across different datasets"""
        # Map common column name variations
        column_mappings = {
            'email': 'text',
            'body': 'text',
            'content': 'text',
            'message': 'text',
            'email_text': 'text',
            'label': 'is_phishing',
            'class': 'is_phishing',
            'type': 'is_phishing',
            'spam': 'is_phishing',
            'phishing': 'is_phishing'
        }
        
        # Rename columns
        for old_name, new_name in column_mappings.items():
            if old_name in df.columns:
                df = df.rename(columns={old_name: new_name})
        
        # Ensure 'is_phishing' is binary (0 or 1)
        if 'is_phishing' in df.columns:
            df['is_phishing'] = df['is_phishing'].map({
                'phishing': 1, 'legitimate': 0, 'ham': 0, 'spam': 1,
                'Phishing': 1, 'Legitimate': 0, 'Ham': 0, 'Spam': 1,
                1: 1, 0: 0, '1': 1, '0': 0, True: 1, False: 0
            })
        
        # Keep only necessary columns
        if 'text' in df.columns and 'is_phishing' in df.columns:
            df = df[['text', 'is_phishing']].dropna()
        
        return df
    
    def _generate_sample_dataset(self) -> pd.DataFrame:
        """Generate a sample dataset for demonstration"""
        print("Generating sample dataset...")
        
        # Sample phishing emails
        phishing_samples = [
            "URGENT: Your account will be suspended! Click here immediately to verify your identity and password.",
            "Congratulations! You've won $1,000,000! Provide your bank account and SSN to claim your prize now!",
            "Security Alert: Unusual activity detected. Confirm your credit card details within 24 hours.",
            "Your PayPal account has been limited. Update your payment information at http://paypa1-secure.xyz",
            "Dear customer, your package is waiting. Pay shipping fee with credit card: http://fedex-track.tk",
            "FINAL NOTICE: Verify your Microsoft account now or lose access forever! Enter password here.",
            "IRS Tax Refund: $5,432 pending. Submit your Social Security Number to receive payment.",
            "Amazon: Your order #12345 failed. Update billing info immediately: http://amaz0n-secure.com",
            "Your email will be deleted in 48 hours! Verify now by providing your username and password.",
            "Congratulations! You're selected for a $500 Walmart gift card. Enter your details to claim."
        ]
        
        # Sample legitimate emails
        legitimate_samples = [
            "Hi team, just wanted to follow up on yesterday's meeting. Let me know if you have any questions.",
            "Your package has been delivered. Track your shipment at amazon.com using order number ABC123.",
            "Thank you for your purchase. Your receipt is attached. Contact us if you need assistance.",
            "Reminder: Your subscription renews next month. Manage your subscription in your account settings.",
            "Newsletter: Check out our latest blog posts and updates from this week.",
            "Meeting scheduled for 2pm tomorrow. Conference room B. Agenda attached.",
            "Your flight confirmation for booking #XYZ789. Check in online 24 hours before departure.",
            "Welcome to our service! Here's a quick guide to get you started with your new account.",
            "Password reset successful. If you didn't request this, please contact our support team.",
            "Your monthly statement is now available. View it by logging into your account dashboard."
        ]
        
        # Create DataFrame
        data = []
        
        # Add phishing samples
        for email in phishing_samples:
            data.append({'text': email, 'is_phishing': 1})
        
        # Add legitimate samples
        for email in legitimate_samples:
            data.append({'text': email, 'is_phishing': 0})
        
        # Duplicate to have more training data
        df = pd.DataFrame(data * 50)  # 1000 total samples
        
        print(f"Generated {len(df)} sample emails")
        return df
    
    def extract_features(self, texts: pd.Series) -> pd.DataFrame:
        """
        Extract hand-crafted features from emails
        
        Args:
            texts: Series of email texts
            
        Returns:
            DataFrame with extracted features
        """
        features = []
        
        for text in texts:
            # Use PhishingDetector to extract features
            analysis = self.feature_detector.analyze_email(text)
            
            # Create feature vector
            feature_dict = {
                'urgency_score': len(analysis['urgency_tactics'].get('urgency_keywords', [])),
                'has_urgency': int(analysis['urgency_tactics'].get('detected', False)),
                'has_sensitive_request': int(analysis['sensitive_info_requests'].get('detected', False)),
                'sensitive_count': len(analysis['sensitive_info_requests'].get('requested_info', [])),
                'has_suspicious_links': int(analysis['link_analysis'].get('detected', False)),
                'link_count': analysis['link_analysis'].get('total_links', 0),
                'has_grammar_issues': int(analysis['grammar_issues'].get('detected', False)),
                'exclamation_marks': text.count('!'),
                'question_marks': text.count('?'),
                'url_count': len(re.findall(r'http[s]?://', text)),
                'has_caps': int(sum(1 for c in text if c.isupper()) / max(len(text), 1) > 0.2),
                'length': len(text),
                'word_count': len(text.split())
            }
            
            features.append(feature_dict)
        
        return pd.DataFrame(features)
    
    def train(self, df: pd.DataFrame) -> Dict:
        """
        Train the phishing detection model
        
        Args:
            df: DataFrame with 'text' and 'is_phishing' columns
            
        Returns:
            Dictionary with training metrics
        """
        print("\n" + "="*60)
        print("Training Phishing Detection Model")
        print("="*60)
        
        # Prepare data
        X_text = df['text']
        y = df['is_phishing']
        
        # Split data
        X_train_text, X_test_text, y_train, y_test = train_test_split(
            X_text, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {len(X_train_text)} samples")
        print(f"Test set: {len(X_test_text)} samples")
        
        # Extract TF-IDF features
        print("\nExtracting TF-IDF features...")
        X_train_tfidf = self.vectorizer.fit_transform(X_train_text)
        X_test_tfidf = self.vectorizer.transform(X_test_text)
        
        # Extract hand-crafted features
        print("Extracting custom features...")
        X_train_custom = self.extract_features(X_train_text)
        X_test_custom = self.extract_features(X_test_text)
        
        # Combine features
        from scipy.sparse import hstack
        X_train = hstack([X_train_tfidf, X_train_custom.values])
        X_test = hstack([X_test_tfidf, X_test_custom.values])
        
        # Train multiple models and compare
        models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'Naive Bayes': MultinomialNB()
        }
        
        results = {}
        best_score = 0
        best_model_name = None
        
        for name, model in models.items():
            print(f"\nTraining {name}...")
            model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            print(f"{name} Accuracy: {accuracy:.4f}")
            print(f"\nClassification Report:\n{classification_report(y_test, y_pred)}")
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'predictions': y_pred
            }
            
            if accuracy > best_score:
                best_score = accuracy
                best_model_name = name
                self.model = model
        
        print("\n" + "="*60)
        print(f"Best Model: {best_model_name} (Accuracy: {best_score:.4f})")
        print("="*60)
        
        # Final confusion matrix
        print(f"\nConfusion Matrix ({best_model_name}):")
        print(confusion_matrix(y_test, results[best_model_name]['predictions']))
        
        return {
            'best_model': best_model_name,
            'best_accuracy': best_score,
            'all_results': results
        }
    
    def save_model(self, model_dir: str = 'models/'):
        """Save trained model and vectorizer"""
        os.makedirs(model_dir, exist_ok=True)
        
        model_path = os.path.join(model_dir, 'phishing_model.pkl')
        vectorizer_path = os.path.join(model_dir, 'vectorizer.pkl')
        
        joblib.dump(self.model, model_path)
        joblib.dump(self.vectorizer, vectorizer_path)
        
        print(f"\nModel saved to {model_path}")
        print(f"Vectorizer saved to {vectorizer_path}")
    
    def load_model(self, model_dir: str = 'models/'):
        """Load trained model and vectorizer"""
        model_path = os.path.join(model_dir, 'phishing_model.pkl')
        vectorizer_path = os.path.join(model_dir, 'vectorizer.pkl')
        
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        
        print(f"Model loaded from {model_path}")
        print(f"Vectorizer loaded from {vectorizer_path}")


def main():
    """Main training pipeline"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     Phishing Detection Model Training Pipeline           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Initialize trainer
    trainer = PhishingModelTrainer()
    
    # Load datasets
    df = trainer.load_datasets()
    
    # Train models
    results = trainer.train(df)
    
    # Save best model
    trainer.save_model()
    
    print("\n✓ Training complete!")
    print("\nTo use the trained model:")
    print("1. Load it in phishing_detector.py")
    print("2. Use it alongside rule-based detection for enhanced accuracy")
    

if __name__ == "__main__":
    # Ensure directories exist
    os.makedirs('datasets', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    # Run training
    main()
