#!/usr/bin/env python3
"""
🎯 PHISHING DETECTOR - UTILS FIXED pentru modelul tău specific
Ensemble System: 30% RandomForest + 70% Hibrid îmbunătățit
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

def make_json_serializable(obj):
    """Convertește obiecte numpy/pandas la tipuri Python JSON serializable"""
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
        return str(obj)

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

# Domenii legitime
LEGIT_DOMAINS = [
    'google.com', 'facebook.com', 'paypal.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'netflix.com', 'instagram.com',
    'ebay.com', 'linkedin.com', 'bankofamerica.com', 'github.com',
    'youtube.com', 'twitter.com', 'zoom.us', 'slack.com'
]

# ============================================
# EMAIL FEATURE EXTRACTION (compatibil cu modelul tău)
# ============================================

def extract_email_features(email_content, subject=None, sender=None):
    """
    Extrage 16 features din email-uri pentru modelul RandomForest
    COMPATIBIL cu modelul tău [0, 1] classes
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
# RANDOMFOREST MODEL HANDLING (pentru modelul tău)
# ============================================

def load_randomforest_model():
    """Încarcă modelul RandomForest din căile posibile"""
    model_paths = [
        'RandomForest/RandomForest.joblib',
        'RandomForest.joblib',
        '../RandomForest/RandomForest.joblib'
    ]
    
    for path in model_paths:
        if os.path.exists(path):
            try:
                model = joblib.load(path)
                print(f"✅ Model loaded from: {path}")
                print(f"   Type: {type(model)}")
                
                # Verifică classes pentru modelul tău
                if hasattr(model, 'classes_'):
                    print(f"   Classes: {model.classes_}")
                elif hasattr(model, 'named_steps'):
                    # Este pipeline
                    for step_name, step in model.named_steps.items():
                        if hasattr(step, 'classes_'):
                            print(f"   Classes in {step_name}: {step.classes_}")
                
                return model
            except Exception as e:
                print(f"❌ Failed to load {path}: {e}")
                continue
    
    print("⚠️ No RandomForest model found!")
    return None

def predict_with_randomforest(email_content, subject="", sender=""):
    """
    Predicție cu RandomForest - FIXED pentru modelul tău cu classes [0, 1]
    
    Returns:
        tuple (phishing_score, confidence) unde:
        - phishing_score: 0-1 (0=safe, 1=phishing) - compatibil cu modelul tău
        - confidence: 0-1 (încrederea în predicție)
    """
    try:
        model = load_randomforest_model()
        if model is None:
            print("🔄 RandomForest unavailable - using fallback")
            return heuristic_rf_fallback(email_content, subject, sender)
        
        features = extract_email_features(email_content, subject, sender)
        features_df = features.to_frame().T
        
        try:
            # Pentru modelul tău cu classes [0, 1]
            probabilities = model.predict_proba(features_df)[0]
            
            if len(probabilities) == 2:
                # [prob_class_0, prob_class_1] = [prob_legitimate, prob_phishing]
                phishing_probability = probabilities[1]  # Class 1 = phishing
                confidence = max(probabilities)
            else:
                # Fallback
                prediction = model.predict(features_df)[0]
                phishing_probability = float(prediction)
                confidence = max(probabilities)
            
            # Asigură-te că e în range corect
            phishing_score = max(0.0, min(1.0, float(phishing_probability)))
            confidence = max(0.0, min(1.0, float(confidence)))
            
            print(f"🤖 RandomForest: phishing_score={phishing_score:.3f}, confidence={confidence:.3f}")
            return phishing_score, confidence
            
        except Exception as e:
            if "feature names should match" in str(e) or "X has" in str(e):
                print("⚠️ Model trained for different features - using adaptive approach")
                return adaptive_rf_prediction(features)
            else:
                raise e
                
    except Exception as e:
        print(f"❌ RandomForest error: {e}")
        return heuristic_rf_fallback(email_content, subject, sender)

def adaptive_rf_prediction(features):
    """Predicție adaptivă când modelul RF nu e compatibil cu features"""
    suspicious_ratio = features['email_suspicious_word_count'] / max(features['email_word_count'], 1)
    urgency_factor = min(1.0, features['email_exclamations'] * 0.2)
    sender_factor = features['sender_domain_suspicious'] * 0.3
    
    adaptive_score = min(0.9, suspicious_ratio * 1.5 + urgency_factor + sender_factor)
    
    print(f"🔧 Adaptive RandomForest: score={adaptive_score:.3f}")
    return float(adaptive_score), 0.6

def heuristic_rf_fallback(email_content, subject, sender):
    """Fallback heuristic când RF nu e disponibil"""
    full_text = f"{subject} {email_content}".lower()
    
    phishing_score = 0.0
    
    # Cuvinte cheie high-priority
    high_keywords = ['urgent', 'click', 'verify', 'suspended', 'limited']
    high_count = sum(1 for word in high_keywords if word in full_text)
    phishing_score += min(0.4, high_count * 0.1)
    
    # Sender suspect
    if sender and '@' in sender:
        sender_domain = sender.split('@')[-1].lower()
        if 'fake' in sender_domain or sender_domain not in LEGIT_DOMAINS:
            phishing_score += 0.3
    
    # Urgență + exclamations
    if 'urgent' in full_text and '!' in subject:
        phishing_score += 0.4
    
    phishing_score = min(1.0, phishing_score)
    
    print(f"🔄 Heuristic fallback: score={phishing_score:.3f}")
    return float(phishing_score), 0.7

# ============================================
# HYBRID ALGORITHM ÎMBUNĂTĂȚIT (din background.js)
# ============================================

def detect_phishing_hybrid(email_data):
    """
    Algoritmul hibrid ÎMBUNĂTĂȚIT din background.js
    FIXED pentru a detecta mai bine cazuri ca "URGENT! Click here!"
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
    
    # 1. CUVINTE CHEIE PHISHING ÎMBUNĂTĂȚIT (max 0.35 points)
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
        # ÎMBUNĂTĂȚIRE: Scor mai mare pentru cuvinte cheie
        keyword_score = min(0.35, keyword_count * 0.08)  # Era 0.05, acum 0.08
        score += keyword_score
        reasons.append(f"Cuvinte cheie suspecte: {keyword_count}")
    
    # 2. LINK-URI SUSPECTE (max 0.25 points) 
    suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
    suspicious_link_count = 0
    
    for link in links:
        if any(domain in link.lower() for domain in suspicious_domains):
            suspicious_link_count += 1
    
    if suspicious_link_count > 0:
        link_score = min(0.25, suspicious_link_count * 0.15)
        score += link_score
        reasons.append(f"Link-uri suspecte: {suspicious_link_count}")
    
    # 3. PATTERN-URI SENSIBILE (0.25 points)
    sensitive_patterns = [
        r'enter.{1,20}(password|credentials)',
        r'(confirm|update|verify).{1,20}(details|information)',
        r'(credit.?card|card.?number)',
        r'bank.{1,30}(details|login|account)'
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            score += 0.25
            reasons.append("Solicită informații sensibile")
            break
    urgency_phrases = ['urgent', 'immediate', 'action required', 'expires']
    urgency_score = 0
    
    if any(phrase in subject.lower() for phrase in urgency_phrases):
        urgency_score += 0.2
        reasons.append("Tonalitate urgentă în subject")

    if any(phrase in body.lower() for phrase in urgency_phrases):
        urgency_score += 0.1
        if "Tonalitate urgentă în subject" not in reasons:
            reasons.append("Tonalitate urgentă")
    
    score += min(0.3, urgency_score)
    dangerous_combinations = [
        ('urgent', 'click', 0.4, "Combinație URGENT + CLICK"),
        ('urgent', 'verify', 0.3, "Combinație URGENT + VERIFY"),
        ('click', 'here', 0.25, "Combinație CLICK HERE"),
        ('suspended', 'verify', 0.35, "Combinație SUSPENDED + VERIFY")
    ]
    
    for word1, word2, points, description in dangerous_combinations:
        if word1 in text_lower and word2 in text_lower:
            score += points
            reasons.append(description)
            break  # Doar o combinație
    
    # 6. ÎMBUNĂTĂȚIRE: SENDER ANALYSIS (max 0.25 points)
    sender_score = 0
    if sender:
        sender_lower = sender.lower()
        
        # Sender evident fals
        if 'fake' in sender_lower or '@fake' in sender_lower:
            sender_score += 0.25
            reasons.append("Sender evident fals")
        # Sender suspect (nu e în domenii legitime)
        elif '@' in sender:
            sender_domain = sender.split('@')[-1].lower()
            if sender_domain not in LEGIT_DOMAINS:
                sender_score += 0.15
                reasons.append("Sender din domeniu suspect")
    
    score += sender_score
    
    # 7. SUBJECT ANALYSIS ÎMBUNĂTĂȚIT (max 0.2 points)
    subject_score = 0
    if subject:
        # Subject foarte scurt + urgent
        if len(subject) < 20 and 'urgent' in subject.lower():
            subject_score += 0.15
            reasons.append("Subject scurt și urgent")
        
        # Multiple exclamații
        if subject.count('!') >= 2:
            subject_score += 0.1
            reasons.append("Subject cu multiple exclamări")
        elif subject.count('!') == 1 and len(subject) < 15:
            subject_score += 0.05
            reasons.append("Subject scurt cu exclamație")
    
    score += min(0.2, subject_score)
    
    score = max(0.0, min(1.0, score))
    
    if not reasons:
        reasons.append("Nu am detectat indicatori de phishing")
    
    return float(score), reasons

def ensemble_predict_email(email_data, alfa=0.3):
    """
    🎯 ENSEMBLE FIXED pentru modelul tău cu classes [0, 1]
    
    Formula: final_score = RF_phishing_score * alfa + hibrid_score * (1-alfa)
    Ambele scoruri sunt phishing probability (0-1)
    
    ÎMBUNĂTĂȚIRI:
    - Threshold scăzut la 0.35 (era 0.5)
    - Algoritmul hibrid îmbunătățit pentru cazuri ca "URGENT! Click here!"
    - RandomForest interpretat corect pentru classes [0, 1]
    """
    
    print(f"🎯 Starting ensemble analysis (alfa={alfa})...")
    
    try:
        hibrid_score, hibrid_reasons = detect_phishing_hybrid(email_data)
        print(f"🔄 Hibrid score: {hibrid_score:.3f}")
    
        rf_phishing_score, rf_confidence = predict_with_randomforest(
            email_data.get('body', ''),
            email_data.get('subject', ''),
            email_data.get('sender', '')
        )
        print(f"🤖 RandomForest phishing score: {rf_phishing_score:.3f}")
        
        # ENSEMBLE FORMULA: ambele scoruri sunt phishing probability
        final_score = rf_phishing_score * alfa + hibrid_score * (1 - alfa)
        final_score = max(0.0, min(1.0, final_score))
        
        # DECIZIE cu threshold ÎMBUNĂTĂȚIT (0.35 în loc de 0.5)
        PHISHING_THRESHOLD = 0.35  # SCĂZUT pentru mai bună detectare
        is_phishing = final_score > PHISHING_THRESHOLD
        
        # REASONS
        reasons = hibrid_reasons.copy() if hibrid_reasons else []
        
        # Adaugă informații RandomForest dacă sunt relevante
        if rf_confidence > 0.6:
            if rf_phishing_score > 0.7:
                reasons.insert(0, f"Model AI: risc foarte înalt ({rf_phishing_score:.2f})")
            elif rf_phishing_score > 0.5:
                reasons.insert(0, f"Model AI: risc înalt ({rf_phishing_score:.2f})")
        
        # Limitează la 5 motive
        reasons = reasons[:5]
        
        # REZULTAT FINAL
        result = {
            'isPhishing': bool(is_phishing),
            'score': float(final_score),
            'reasons': [str(reason) for reason in reasons],
            'method': f'ensemble_fixed_{int(alfa*100)}%_rf_{int((1-alfa)*100)}%_hibrid',
            'breakdown': {
                'rf_score': float(rf_phishing_score),
                'rf_confidence': float(rf_confidence),
                'hibrid_score': float(hibrid_score),
                'hibrid_reasons': [str(reason) for reason in hibrid_reasons] if hibrid_reasons else [],
                'formula': f'{rf_phishing_score:.3f} * {alfa} + {hibrid_score:.3f} * {1-alfa:.1f} = {final_score:.3f}',
                'weights': f'{int(alfa*100)}% RandomForest + {int((1-alfa)*100)}% Hibrid Enhanced',
                'threshold': PHISHING_THRESHOLD,
                'threshold_note': f'Score > {PHISHING_THRESHOLD} = phishing (scăzut pentru mai bună detectare)'
            }
        }
        
        decision_text = 'PHISHING' if is_phishing else 'SAFE'
        print(f"🎯 Final result: {result['method']} = {final_score:.3f} ({decision_text})")
        
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
                'weights': 'error',
                'threshold': 0.35,
                'threshold_note': 'Error fallback'
            }
        }


def test_problematic_email():
    """Testează email-ul problematic din exemplul tău"""
    print("🧪 TESTING PROBLEMATIC EMAIL - FIXED VERSION")
    print("=" * 60)
    
    problematic_email = {
        'subject': 'URGENT!',
        'body': 'Click here!',
        'sender': 'fake@fake.com',
        'links': []
    }
    
    print("📧 Email problematic din exemplul tău:")
    print(f"   Subject: '{problematic_email['subject']}'")
    print(f"   Body: '{problematic_email['body']}'")
    print(f"   Sender: '{problematic_email['sender']}'")
    
    result = ensemble_predict_email(problematic_email)
    
    print(f"\n🎯 REZULTAT FIXED:")
    print(f"   Clasificare: {'🚨 PHISHING' if result['isPhishing'] else '✅ SAFE'}")
    print(f"   Score: {result['score']:.3f}")
    print(f"   Threshold: {result['breakdown']['threshold']}")
    print(f"   Method: {result['method']}")
    print(f"   Formula: {result['breakdown']['formula']}")
    
    print(f"\n📝 Motive detectate:")
    for i, reason in enumerate(result['reasons'], 1):
        print(f"   {i}. {reason}")
    
    print(f"\n🔧 Breakdown detaliat:")
    print(f"   🤖 RandomForest: {result['breakdown']['rf_score']:.3f}")
    print(f"   🔄 Hibrid Enhanced: {result['breakdown']['hibrid_score']:.3f}")
    print(f"   ⚖️ Weights: {result['breakdown']['weights']}")
    
    if result['isPhishing']:
        print(f"\n✅ SUCCESS! Email-ul evident suspect este acum detectat ca PHISHING!")
        print(f"🎯 Îmbunătățirile au funcționat!")
    else:
        print(f"\n⚠️ Email-ul încă nu e detectat. Pot să încerc și alte optimizări...")
    
    return result

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'test':
            test_problematic_email()
        else:
            print("Usage: python utils.py test")
    else:
        print("🎯 Phishing Detector Utils - FIXED VERSION")
        print("Usage:")
        print("  python utils.py test  # Test problematic email fix")