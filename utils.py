#!/usr/bin/env python3
"""
🎯 PHISHING DETECTOR - UTILS FINALI CU JSON FIX
Ensemble System: 30% RandomForest + 70% Hibrid
"""

import os
import re
import joblib
import warnings
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from collections import Counter

# Ascunde warning-urile sklearn
warnings.filterwarnings('ignore', category=UserWarning)

# ============================================
# JSON SERIALIZATION HELPER
# ============================================

def make_json_serializable(obj):
    """
    Convertește obiecte numpy/pandas la tipuri Python JSON serializable
    Fix pentru TypeError: Object of type bool is not JSON serializable
    """
    if isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    elif isinstance(obj, (np.integer, int)):
        return int(obj)
    elif isinstance(obj, (np.floating, float)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: make_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(item) for item in obj]
    elif isinstance(obj, (pd.Series, pd.DataFrame)):
        return make_json_serializable(obj.to_dict())
    else:
        return str(obj)  # Convertește la string ca fallback

# ============================================
# CONSTANTE
# ============================================

# Cuvinte cheie phishing (pentru email features)
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify', 'banking', 'password', 'credit card', 'social security',
    'click', 'suspicious', 'required', 'limited', 'expire', 'paypal', 'atm',
    'authenticate', 'validation', 'fraud', 'lottery', 'winning', 'prize', 'claim',
    'congrats', 'congratulation', 'gift', 'free', 'unexpected', 'inheritance',
    'suspended', 'unauthorized', 'immediate', 'action', 'invoice',
    'limited time', 'offer', 'tax', 'refund', 'wire transfer', 'money',
    'bitcoin', 'crypto', 'investment', 'double', 'profit', 'beneficiary',
    'identity', 'theft', 'compromise', 'hacked', 'restriction', 'disable'
]

# Domenii legitime (pentru sender validation)
LEGIT_DOMAINS = [
    'google.com', 'facebook.com', 'paypal.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'netflix.com', 'instagram.com',
    'ebay.com', 'linkedin.com', 'bankofamerica.com', 'github.com',
    'youtube.com', 'twitter.com', 'zoom.us', 'slack.com'
]

# ============================================
# EMAIL FEATURE EXTRACTION
# ============================================

def extract_email_features(email_content, subject=None, sender=None):
    """
    Extrage 16 features din email-uri pentru modelul RandomForest
    
    Returns:
        pandas.Series cu 16 features numerice
    """
    features = {}
    
    # Normalizează inputs
    email_content = str(email_content) if email_content else ""
    subject = str(subject) if subject else ""
    sender = str(sender) if sender else ""
    
    # 1-6: Basic content features
    features['email_content_length'] = len(email_content)
    features['email_word_count'] = len(email_content.split())
    features['email_line_count'] = email_content.count('\n')
    features['email_exclamations'] = email_content.count('!')
    features['email_questions'] = email_content.count('?')
    features['email_caps_ratio'] = (
        sum(1 for c in email_content if c.isupper()) / len(email_content) 
        if email_content else 0
    )
    
    # 7: Suspicious content
    features['email_suspicious_word_count'] = sum(
        1 for word in SUSPICIOUS_KEYWORDS 
        if word.lower() in email_content.lower()
    )
    
    # 8-10: Subject features
    features['subject_length'] = len(subject)
    features['subject_exclamations'] = subject.count('!')
    features['subject_suspicious_words'] = sum(
        1 for word in SUSPICIOUS_KEYWORDS 
        if word.lower() in subject.lower()
    )
    
    # 11-13: Sender features
    features['sender_length'] = len(sender)
    features['sender_has_at'] = int('@' in sender)
    
    if '@' in sender:
        sender_domain = sender.split('@')[-1].lower()
        features['sender_domain_suspicious'] = int(sender_domain not in LEGIT_DOMAINS)
    else:
        features['sender_domain_suspicious'] = 1
    
    # 14-16: URL features
    urls_in_email = re.findall(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        email_content
    )
    
    features['email_url_count'] = len(urls_in_email)
    features['email_has_urls'] = int(len(urls_in_email) > 0)
    features['urls'] = len(urls_in_email)  # Pentru compatibilitate
    
    return pd.Series(features)

# ============================================
# RANDOMFOREST MODEL HANDLING
# ============================================

def load_randomforest_model():
    """
    Încarcă modelul RandomForest din căile posibile
    
    Returns:
        model sklearn sau None dacă nu găsește
    """
    model_paths = [
        'RandomForest/RandomForest.joblib',
        'RandomForest.joblib',
        '../RandomForest/RandomForest.joblib',
        # Căi pentru email models din SecureME
        'C:/Users/Ioana/Documents/SecureME/classifier/classifier/email_models/randomforest/rf_model.pkl',
        'email_models/randomforest/rf_model.pkl'
    ]
    
    for path in model_paths:
        if os.path.exists(path):
            try:
                model = joblib.load(path)
                print(f"✅ Model loaded from: {path}")
                print(f"   Type: {type(model)}")
                return model
            except Exception as e:
                print(f"❌ Failed to load {path}: {e}")
                continue
    
    print("⚠️ No RandomForest model found!")
    return None

def predict_with_randomforest(email_content, subject="", sender=""):
    """
    Predicție cu RandomForest - cu fallback inteligent
    
    Returns:
        tuple (score, confidence) unde:
        - score: 0-1 (0=legitimate, 1=phishing)  
        - confidence: 0-1 (încrederea în predicție)
    """
    try:
        # Încarcă modelul
        model = load_randomforest_model()
        if model is None:
            print("🔄 RandomForest unavailable - using neutral score")
            return 0.5, 0.0
        
        # Extract features
        features = extract_email_features(email_content, subject, sender)
        features_df = features.to_frame().T
        
        # Încearcă predicția
        try:
            prediction = model.predict(features_df)[0]
            probabilities = model.predict_proba(features_df)[0]
            confidence = probabilities.max()
            
            # Normalizează scorul (0=legitimate, 1=phishing)
            rf_score = float(prediction)
            
            print(f"🤖 RandomForest: score={rf_score:.3f}, confidence={confidence:.3f}")
            return float(rf_score), float(confidence)
            
        except ValueError as e:
            if "feature names should match" in str(e):
                print("⚠️ Model trained for different features - using adaptive approach")
                
                # Încearcă să adapteze - returnează un scor bazat pe features simple
                suspicious_ratio = (
                    features['email_suspicious_word_count'] / 
                    max(features['email_word_count'], 1)
                )
                adaptive_score = min(0.8, suspicious_ratio * 2)  # Cap la 0.8
                
                print(f"🔧 Adaptive RandomForest: score={adaptive_score:.3f}")
                return float(adaptive_score), 0.5  # Confidence moderată
            else:
                raise e
                
    except Exception as e:
        print(f"❌ RandomForest error: {e}")
        return 0.5, 0.0

# ============================================
# HYBRID ALGORITHM (TRADUS DIN BACKGROUND.JS)
# ============================================

def detect_phishing_hybrid(email_data):
    """
    Algoritmul hibrid original din background.js, tradus în Python
    
    Args:
        email_data: dict cu keys: subject, body, links, sender
        
    Returns:
        tuple (score, reasons) unde:
        - score: 0-1 (probabilitatea de phishing)
        - reasons: lista cu motivele detectării
    """
    subject = email_data.get('subject', '')
    body = email_data.get('body', '')
    links = email_data.get('links', [])
    sender = email_data.get('sender', '')
    
    # Trusted senders - returnează imediat 0
    trusted_senders = [
        "newsletter@company.com", "support@google.com", "no-reply@linkedin.com",
        "info@amazon.com", "notifications@github.com", "news@medium.com",
        "noreply@youtube.com", "billing@microsoft.com"
    ]
    
    if any(trusted in sender.lower() for trusted in trusted_senders):
        return 0.0, ["Expeditor de încredere"]
    
    # Combină textul
    text = subject + ' ' + body
    text_lower = text.lower()
    
    score = 0.0
    reasons = []
    
    # 1. Cuvinte cheie phishing (max 0.25 points)
    phishing_keywords = [
        'urgent', 'verify', 'banking', 'password', 'credit card', 'social security',
        'click', 'suspicious', 'required', 'limited', 'expire', 'paypal', 'atm',
        'authenticate', 'validation', 'fraud', 'lottery', 'winning', 'prize', 'claim',
        'congrats', 'congratulation', 'gift', 'free', 'unexpected', 'inheritance',
        'suspended', 'unauthorized', 'immediate', 'action', 'invoice',
        'limited time', 'offer', 'tax', 'refund', 'wire transfer', 'money',
        'bitcoin', 'crypto', 'investment', 'double', 'profit', 'beneficiary',
        'identity', 'theft', 'compromise', 'hacked', 'restriction', 'disable'
    ]
    
    keyword_count = sum(1 for keyword in phishing_keywords if keyword in text_lower)
    if keyword_count > 0:
        keyword_score = min(0.25, keyword_count * 0.05)
        score += keyword_score
        reasons.append(f"Cuvinte cheie suspecte: {keyword_count}")
    
    # 2. Link-uri suspecte (max 0.3 points)
    suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
    suspicious_link_count = 0
    
    for link in links:
        if any(domain in link.lower() for domain in suspicious_domains):
            suspicious_link_count += 1
    
    if suspicious_link_count > 0:
        link_score = min(0.3, suspicious_link_count * 0.15)
        score += link_score
        reasons.append(f"Link-uri suspecte: {suspicious_link_count}")
    
    # 3. Pattern-uri sensibile (0.3 points)
    sensitive_patterns = [
        r'enter.{1,20}(password|credentials)',
        r'(confirm|update|verify).{1,20}(details|information)',
        r'(credit.?card|card.?number)',
        r'bank.{1,30}(details|login|account)'
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            score += 0.3
            reasons.append("Solicită informații sensibile")
            break
    
    # 4. Tonalitate urgentă (0.15 points)
    urgency_phrases = ['urgent', 'immediate', 'action required', 'expires']
    if any(phrase in text_lower for phrase in urgency_phrases):
        score += 0.15
        reasons.append("Tonalitate urgentă")
    
    # 5. Pattern-uri phishing (0.2 points)
    phishing_patterns = [
        r'(we.{1,10}detected.{1,20}suspicious)',
        r'(verify.{1,10}account.{1,10}prevent)',
        r'(unusual.{1,10}activity)',
        r'(account.{1,10}suspended)',
        r'(click.{1,10}link.{1,10}below)'
    ]
    
    pattern_matches = sum(1 for pattern in phishing_patterns if re.search(pattern, text, re.IGNORECASE))
    if pattern_matches >= 2:
        score += 0.2
        reasons.append("Pattern-uri lingvistice phishing")
    
    # Normalizează scorul
    score = max(0.0, min(1.0, score))
    
    if not reasons:
        reasons.append("Nu am detectat indicatori de phishing")
    
    return float(score), reasons

# ============================================
# ENSEMBLE PREDICTION (FORMULA DIN TODO)
# ============================================

def ensemble_predict_email(email_data, alfa=0.3):
    """
    🎯 FUNCȚIA ENSEMBLE PRINCIPALĂ
    
    Formula din TODO: final_score = A * alfa + (1-alfa) * B
    A = RandomForest (30%), B = Algoritm hibrid (70%)
    
    Args:
        email_data: dict cu subject, body, links, sender
        alfa: greutatea RandomForest (default 0.3 = 30%)
        
    Returns:
        dict cu rezultatul final (JSON serializable)
    """
    
    print(f"🎯 Starting ensemble analysis (alfa={alfa})...")
    
    try:
        # B = Algoritm hibrid (70%)
        hibrid_score, hibrid_reasons = detect_phishing_hybrid(email_data)
        print(f"🔄 Hibrid score: {hibrid_score:.3f}")
        
        # A = RandomForest (30%)
        rf_score, rf_confidence = predict_with_randomforest(
            email_data.get('body', ''),
            email_data.get('subject', ''),
            email_data.get('sender', '')
        )
        print(f"🤖 RandomForest score: {rf_score:.3f}")
        
        # Formula din TODO: final_score = A * alfa + (1-alfa) * B
        final_score = rf_score * alfa + hibrid_score * (1 - alfa)
        final_score = max(0.0, min(1.0, final_score))
        
        # Decizie (prag 0.5 pentru mai bună detectare)
        is_phishing = final_score > 0.5
        
        # Combină motivele
        reasons = hibrid_reasons.copy() if hibrid_reasons else []
        if rf_confidence > 0.5:
            reasons.append(f"RandomForest: {rf_score:.2f} (conf: {rf_confidence:.2f})")
        
        # Rezultat final - ASIGURĂ-TE CĂ E JSON SERIALIZABLE
        result = {
            'isPhishing': bool(is_phishing),
            'score': float(final_score),
            'reasons': [str(reason) for reason in reasons[:5]],
            'method': f'ensemble_{int(alfa*100)}%_rf_{int((1-alfa)*100)}%_hibrid',
            'breakdown': {
                'rf_score': float(rf_score),
                'rf_confidence': float(rf_confidence),
                'hibrid_score': float(hibrid_score),
                'hibrid_reasons': [str(reason) for reason in hibrid_reasons] if hibrid_reasons else [],
                'formula': f'{rf_score:.3f} * {alfa} + {hibrid_score:.3f} * {1-alfa:.1f} = {final_score:.3f}',
                'weights': f'{int(alfa*100)}% RandomForest + {int((1-alfa)*100)}% Hibrid'
            }
        }
        
        print(f"🎯 Final result: {result['method']} = {final_score:.3f} ({'PHISHING' if is_phishing else 'SAFE'})")
        
        # EXTRA SAFE: Convertește totul la JSON serializable
        return make_json_serializable(result)
        
    except Exception as e:
        print(f"❌ Ensemble error: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback safe result
        return {
            'isPhishing': False,
            'score': 0.0,
            'reasons': [f'Eroare în analiză: {str(e)}'],
            'method': 'error_fallback',
            'breakdown': {
                'rf_score': 0.0,
                'rf_confidence': 0.0,
                'hibrid_score': 0.0,
                'hibrid_reasons': [],
                'formula': 'error',
                'weights': 'error'
            }
        }

# ============================================
# TESTING FUNCTIONS
# ============================================

def test_email_features():
    """Test extragerea de features din email-uri"""
    print("📧 Testing email feature extraction...")
    
    test_email = {
        'content': 'URGENT: Your account suspended! Click here: http://fake-site.com',
        'subject': 'URGENT!',
        'sender': 'fake@fake.com'
    }
    
    features = extract_email_features(
        test_email['content'],
        test_email['subject'],
        test_email['sender']
    )
    
    print(f"✅ Extracted {len(features)} features")
    print(f"   Sample: {dict(list(features.items())[:5])}")
    
    return features

def test_ensemble_system():
    """Test complet al sistemului ensemble"""
    print("\n🧪 TESTING ENSEMBLE SYSTEM")
    print("=" * 50)
    
    test_cases = [
        {
            'subject': 'URGENT: Account Suspended!',
            'body': 'Your PayPal account suspended! Click here immediately: http://paypal-fake.com',
            'sender': 'security@paypal-fake.com',
            'links': ['http://paypal-fake.com'],
            'expected': 'phishing'
        },
        {
            'subject': 'Pull Request Merged',
            'body': 'Your GitHub pull request has been merged successfully.',
            'sender': 'notifications@github.com',
            'links': ['https://github.com/user/repo'],
            'expected': 'legitimate'
        },
        {
            'subject': 'Newsletter',
            'body': 'Thank you for subscribing to our weekly newsletter.',
            'sender': 'newsletter@company.com',
            'links': ['https://company.com/unsubscribe'],
            'expected': 'legitimate'
        }
    ]
    
    for i, test_case in enumerate(test_cases):
        print(f"\n📧 Test {i+1} - {test_case['expected']}")
        print(f"   Subject: {test_case['subject']}")
        print(f"   Sender: {test_case['sender']}")
        
        result = ensemble_predict_email(test_case)
        
        print(f"   🎯 Result: {'PHISHING' if result['isPhishing'] else 'SAFE'}")
        print(f"   📊 Score: {result['score']:.3f}")
        print(f"   🔧 Method: {result['method']}")
        print(f"   📝 Reasons: {result['reasons'][:2]}")
        
        # Verifică dacă rezultatul e rezonabil
        expected_phishing = test_case['expected'] == 'phishing'
        actual_phishing = result['isPhishing']
        
        if expected_phishing == actual_phishing:
            print(f"   ✅ CORRECT prediction!")
        else:
            print(f"   ⚠️ Unexpected result (expected {test_case['expected']})")
    
    print(f"\n✅ Ensemble testing completed!")

# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test':
            test_email_features()
            test_ensemble_system()
        elif sys.argv[1] == 'features':
            test_email_features()
        else:
            print("Usage: python utils.py [test|features]")
    else:
        print("🎯 Phishing Detector Utils")
        print("Usage:")
        print("  python utils.py test      # Test ensemble system")
        print("  python utils.py features  # Test feature extraction")