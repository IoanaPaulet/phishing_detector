import Levenshtein
from urllib.parse import urlparse
import string
import pandas as pd
import re
from datetime import datetime
from collections import Counter

suspicious_keywords = [
    'login', 'signin', 'verify', 'update', 'banking', 'account',
    'secure', 'ebay', 'paypal', 'invoice', 'credentials',
    'password', 'confirm', 'webscr', 'security', 'submit',
    'redirect', 'authentication', 'download', 'free', 'bonus',
    'win', 'reset', 'access', 'click', 'alert', 'support',
    'urgent', 'suspended', 'blocked', 'expires', 'immediately'
]

legit_domains = [
    'google.com', 'facebook.com', 'paypal.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'netflix.com', 'instagram.com',
    'ebay.com', 'linkedin.com', 'bankofamerica.com', 'github.com',
    'youtube.com', 'twitter.com', 'zoom.us', 'slack.com'
]

TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'googlemail.com',
    'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazonaws.com',
    'facebook.com', 'meta.com',
    'linkedin.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
    'dropbox.com', 'box.com', 'onedrive.com',
    'salesforce.com', 'hubspot.com',
    
    # Development & Tech
    'github.com', 'gitlab.com', 'stackoverflow.com',
    'atlassian.com', 'jira.com', 'confluence.com',
    'docker.com', 'npmjs.com',
    
    # Entertainment & Media
    'netflix.com', 'spotify.com', 'youtube.com',
    'twitch.tv', 'discord.com',
    
    # Finance & Banking (major ones)
    'paypal.com', 'stripe.com', 'square.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    
    # E-commerce
    'ebay.com', 'etsy.com', 'shopify.com',
    'walmart.com', 'target.com',
    
    # Education & Government TLD patterns
    'edu', 'gov', 'ac.uk', 'edu.au'
]

PHISHING_KEYWORDS = [
    # Urgency
    'urgent', 'immediately', 'asap', 'act now', 'limited time',
    'expires today', 'suspended', 'blocked', 'locked',
    
    # Financial threats
    'account closed', 'payment failed', 'verify payment',
    'update billing', 'refund pending', 'unusual activity',
    
    # Security threats
    'security alert', 'verify identity', 'confirm account',
    'click here to verify', 'login to secure', 'restore access',
    
    # Scam patterns
    'congratulations you won', 'claim your prize', 'lottery winner',
    'free money', 'inheritance', 'tax refund'
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.su', '.top', '.click']



def get_min_levenshtein_distance(url, legit_domains):
    try:
        domain = urlparse(url).netloc.lower()
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2] + '.' + domain_parts[-1]
        else:
            main_domain = domain
        distances = [Levenshtein.distance(main_domain, legit) for legit in legit_domains]
        return min(distances)
    except:
        return 100

def extract_features(url):
    """
    ✅ ENHANCED: Extrage toate caracteristicile URL-ului pentru detectarea phishing-ului
    ROLUL: Transformă URL-ul într-un vector numeric pentru ML
    
    Features extrași:
    - Basic: url_length, num_digits, num_special_chars, etc.
    - Advanced: levenshtein_min, brand_impersonation, suspicious_patterns
    - New: simple_domain_detection, tld_analysis, path_analysis
    """
    features = {}

    # Basic URL characteristics
    features['url_length'] = len(url)
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = sum(c in string.punctuation for c in url)
    features['num_subdomains'] = url.count('.') - 1
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_https'] = int('https' in url.lower())
    features['num_params'] = url.count('?')
    features['num_fragments'] = url.count('#')
    features['num_slashes'] = url.count('/')
    features['has_suspicious_words'] = int(any(word in url.lower() for word in suspicious_keywords))
    
    # TLD Analysis
    try:
        tld = url.split('.')[-1].split('/')[0].split('?')[0]  # Clean TLD extraction
        features['tld_length'] = len(tld)
        features['is_common_tld'] = int(tld in ['com', 'org', 'net', 'edu', 'gov'])
        features['suspicious_tld'] = int(any(sus_tld in url.lower() for sus_tld in SUSPICIOUS_TLDS))
    except:
        features['tld_length'] = 0
        features['is_common_tld'] = 0
        features['suspicious_tld'] = 0
    
    # Advanced pattern detection
    features['has_hex'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    features['repeated_chars'] = int(bool(re.search(r'(.)\1{3,}', url)))
    features['suspicious_word_count'] = sum(word in url.lower() for word in suspicious_keywords)
    features['has_exe'] = int('.exe' in url.lower())
    features['has_zip'] = int('.zip' in url.lower())
    features['has_apk'] = int('.apk' in url.lower())
    features['special_char_ratio'] = features['num_special_chars'] / features['url_length'] if features['url_length'] > 0 else 0
    features['levenshtein_min'] = get_min_levenshtein_distance(url, legit_domains)
    
    # Domain analysis
    try:
        domain = urlparse(url).netloc
        main_domain = domain.split('.')[-2] if len(domain.split('.')) >= 2 else domain
        features['main_domain_length'] = len(main_domain)
    except:
        features['main_domain_length'] = 0

    # ✅ NEW FEATURES for enhanced detection
    
    # Brand impersonation detection
    major_brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple', 'netflix']
    features['impersonates_brand'] = int(any(brand in url.lower() and brand not in urlparse(url).netloc.lower() for brand in major_brands))
    
    # Simple domain detection (helps with real-world URLs)
    features['is_simple_domain'] = int(url.count('/') <= 3 and len(url) < 30)
    
    # Path analysis
    try:
        path = urlparse(url).path
        features['path_depth'] = path.count('/') - 1 if path else 0
        features['path_length'] = len(path) if path else 0
    except:
        features['path_depth'] = 0
        features['path_length'] = 0
    
    # Subdomain analysis
    try:
        subdomain_parts = urlparse(url).netloc.split('.')
        features['subdomain_count'] = len(subdomain_parts) - 2 if len(subdomain_parts) > 2 else 0
        features['long_subdomain'] = int(any(len(part) > 10 for part in subdomain_parts[:-2]) if len(subdomain_parts) > 2 else False)
    except:
        features['subdomain_count'] = 0
        features['long_subdomain'] = 0

    return pd.Series(features)

# ============================================
# EMAIL FEATURE EXTRACTION - FIXED
# ============================================

def extract_email_features(email_content, subject=None, sender=None):
    """
    ✅ FIXED: Extrage caracteristici din email-uri pentru detectarea phishing-ului
    ROLUL: Transformă email-ul într-un vector numeric pentru ML
    
    Features extrași:
    - Basic content: length, word count, exclamations, etc.
    - Suspicious content: suspicious words, caps ratio
    - Subject analysis: length, exclamations, suspicious words
    - Sender analysis: domain validation, structure
    - URL analysis: count, validation
    - ✅ FIXED: Adăugat 'urls' feature pentru compatibilitatea modelului
    """
    features = {}
    
    if not email_content:
        email_content = ""
    
    # Basic content features
    features['email_content_length'] = len(str(email_content))
    features['email_word_count'] = len(str(email_content).split())
    features['email_line_count'] = str(email_content).count('\n')
    features['email_exclamations'] = str(email_content).count('!')
    features['email_questions'] = str(email_content).count('?')
    features['email_caps_ratio'] = sum(1 for c in str(email_content) if c.isupper()) / len(str(email_content)) if email_content else 0
    
    # Suspicious content
    features['email_suspicious_word_count'] = sum(1 for word in suspicious_keywords 
                                                 if word.lower() in str(email_content).lower())
    
    # Subject features
    if subject:
        features['subject_length'] = len(str(subject))
        features['subject_exclamations'] = str(subject).count('!')
        features['subject_suspicious_words'] = sum(1 for word in suspicious_keywords 
                                                  if word.lower() in str(subject).lower())
    else:
        features['subject_length'] = 0
        features['subject_exclamations'] = 0
        features['subject_suspicious_words'] = 0
    
    # Sender features
    if sender:
        features['sender_length'] = len(str(sender))
        features['sender_has_at'] = int('@' in str(sender))
        if '@' in str(sender):
            domain = str(sender).split('@')[-1]
            features['sender_domain_suspicious'] = int(domain not in legit_domains)
        else:
            features['sender_domain_suspicious'] = 1
    else:
        features['sender_length'] = 0
        features['sender_has_at'] = 0
        features['sender_domain_suspicious'] = 1
    
    # URL analysis within email
    urls_in_email = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', 
                              str(email_content))
    features['email_url_count'] = len(urls_in_email)
    features['email_has_urls'] = int(len(urls_in_email) > 0)
    
    # ✅ CRITICAL FIX: Add missing 'urls' feature that model expects
    features['urls'] = len(urls_in_email)
    
    return pd.Series(features)

# ============================================
# PRODUCTION CLASSIFIERS - NEW
# ============================================

def classify_url_production(url, rf_model=None, url_label_encoder=None, selected_features=None):
    """
    ✅ NEW: Production URL classifier cu whitelist + ML hybrid approach
    
    Args:
        url: URL to classify
        rf_model: Trained RandomForest model (optional)
        url_label_encoder: Label encoder (optional)  
        selected_features: Feature list for model (optional)
    
    Returns:
        dict: {
            'prediction': 'benign'/'phishing'/'malware',
            'confidence': float,
            'method': 'whitelist'/'ml_model'/'heuristic',
            'reason': str
        }
    """
    
    # STEP 1: Trusted domains check
    try:
        domain = urlparse(url).netloc.lower()
        
        # Check exact domain match
        is_trusted_exact = any(trusted in domain for trusted in TRUSTED_DOMAINS)
        
        # Check TLD patterns (edu, gov, etc.)
        is_trusted_tld = any(domain.endswith('.' + tld) or domain == tld 
                           for tld in ['edu', 'gov', 'ac.uk', 'edu.au'])
        
        if is_trusted_exact or is_trusted_tld:
            # Double-check: no obvious phishing indicators even from trusted domains
            obvious_phishing = any(keyword in url.lower() for keyword in PHISHING_KEYWORDS[:5])
            
            if not obvious_phishing:
                return {
                    'prediction': 'benign',
                    'confidence': 0.95,
                    'method': 'whitelist',
                    'reason': f'Trusted domain: {domain}'
                }
    except:
        pass
    
    # STEP 2: Heuristic red flags check
    heuristic_result = heuristic_url_classification(url)
    if heuristic_result['confidence'] > 0.8:
        return heuristic_result
    
    # STEP 3: ML prediction pentru unknown domains
    if rf_model and url_label_encoder and selected_features:
        try:
            features = extract_features(url).to_frame().T
            features_selected = features[selected_features]
            
            prediction = rf_model.predict(features_selected)[0] 
            confidence = rf_model.predict_proba(features_selected)[0].max()
            prediction_label = url_label_encoder.inverse_transform([prediction])[0]
            
            return {
                'prediction': prediction_label,
                'confidence': confidence,
                'method': 'ml_model',
                'reason': f'ML classification (features: {len(selected_features)})'
            }
        except Exception as e:
            # Fallback to heuristic if ML fails
            pass
    
    # STEP 4: Fallback to heuristic
    return heuristic_result

def heuristic_url_classification(url):
    """
    ✅ NEW: Heuristic-based URL classification
    Simple rules for obvious phishing detection
    """
    score = 0
    reasons = []
    
    # Red flags detection
    if any(word in url.lower() for word in ['urgent', 'suspended', 'verify', 'confirm']):
        score += 0.3
        reasons.append('urgency keywords')
    
    if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
        score += 0.4
        reasons.append('suspicious TLD')
    
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):  # IP address
        score += 0.5
        reasons.append('IP address instead of domain')
    
    # Levenshtein check for domain similarity
    lev_distance = get_min_levenshtein_distance(url, legit_domains)
    if 1 <= lev_distance <= 2:  # Very close to legitimate domain
        score += 0.4
        reasons.append(f'domain similarity (distance: {lev_distance})')
    
    # Long URLs with many special characters
    if len(url) > 100 and url.count('-') > 5:
        score += 0.2
        reasons.append('suspicious URL structure')
    
    prediction = 'phishing' if score > 0.4 else 'benign'
    confidence = min(0.6 + score, 0.95) if score > 0.4 else max(0.3, 0.8 - score)
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'method': 'heuristic',
        'reason': f'Heuristic rules: {", ".join(reasons)}' if reasons else 'No suspicious indicators'
    }

def classify_email_production(content, subject="", sender=""):
    """
    ✅ NEW: Production email classifier cu whitelist și pattern matching
    
    Returns:
        dict: {
            'prediction': 'Legitimate'/'Phishing',
            'confidence': float,
            'reason': str,
            'method': str
        }
    """
    
    # Normalize inputs
    content = str(content).lower()
    subject = str(subject).lower() 
    sender = str(sender).lower()
    
    # STEP 1: Trusted domain check
    if sender and '@' in sender:
        sender_domain = sender.split('@')[-1]
        
        # Check exact domain match
        is_trusted_exact = sender_domain in TRUSTED_DOMAINS
        
        # Check TLD patterns (edu, gov, etc.)
        is_trusted_tld = any(sender_domain.endswith('.' + tld) or sender_domain == tld 
                           for tld in ['edu', 'gov', 'ac.uk', 'edu.au'])
        
        if is_trusted_exact or is_trusted_tld:
            # Double-check: no obvious phishing indicators even from trusted domains
            obvious_phishing = any(keyword in (content + subject) for keyword in PHISHING_KEYWORDS[:5])
            
            if not obvious_phishing:
                return {
                    'prediction': 'Legitimate',
                    'confidence': 0.95,
                    'reason': f'Trusted domain: {sender_domain}',
                    'method': 'Whitelist'
                }
    
    # STEP 2: Obvious phishing check
    phishing_score = 0
    found_indicators = []
    
    for keyword in PHISHING_KEYWORDS:
        if keyword in (content + subject):
            phishing_score += 1
            found_indicators.append(keyword)
    
    # Check for suspicious URLs (non-https, suspicious domains)
    urls = re.findall(r'http[s]?://([^/\s]+)', content)
    suspicious_urls = []
    
    for url_domain in urls:
        # Check if URL domain matches sender domain
        if sender and '@' in sender:
            sender_domain = sender.split('@')[-1]
            if url_domain != sender_domain and not any(trusted in url_domain for trusted in TRUSTED_DOMAINS):
                suspicious_urls.append(url_domain)
    
    # STEP 3: Scoring & decision
    if phishing_score >= 3 or len(suspicious_urls) >= 2:
        return {
            'prediction': 'Phishing',
            'confidence': min(0.95, 0.7 + (phishing_score * 0.05)),
            'reason': f'Multiple phishing indicators: {found_indicators[:3]}',
            'method': 'Pattern matching'
        }
    
    elif phishing_score >= 2 or len(suspicious_urls) >= 1:
        return {
            'prediction': 'Phishing',
            'confidence': 0.80,
            'reason': f'Phishing indicators: {found_indicators[:2]}',
            'method': 'Pattern matching'
        }
    
    else:
        return {
            'prediction': 'Legitimate',
            'confidence': 0.70,
            'reason': 'No strong phishing indicators found',
            'method': 'Conservative classification'
        }



def tokenize_url(url):
    """
    Împarte URL-ul în token-uri pentru analiza WordCloud
    ROLUL: Extrage cuvintele cheie din URL pentru vizualizare
    
    Exemplu:
    'http://fake-paypal.com/login' → ['http', 'fake', 'paypal', 'com', 'login']
    """
    tokens = re.split(r'[/\=-_.?&=:@]', url.lower())
    tokens = [token for token in tokens if token and len(token) > 2]
    return tokens

def get_top_words(df, columns='url', top_n=15):
    """
    Extrage cele mai frecvente cuvinte din URL-uri pentru o categorie
    ROLUL: Ajută la înțelegerea pattern-urilor în URL-urile malițioase
    """
    all_tokens = []
    for url in df[columns]:
        all_tokens.extend(tokenize_url(url))
    
    return Counter(all_tokens).most_common(top_n)

def plot_wordcloud(df, title):
    """
    Creează WordCloud pentru vizualizarea cuvintelor din URL-uri
    ROLUL: Vizualizare - ajută să vezi ce cuvinte apar des în URL-urile unei categorii
    """
    try:
        from wordcloud import WordCloud
        import matplotlib.pyplot as plt
        
        all_text = ' '.join([' '.join(tokenize_url(url)) for url in df['url']])
        wordcloud = WordCloud(width=800, height=400, background_color='black').generate(all_text)
        plt.figure(figsize=(10, 5))
        plt.imshow(wordcloud, interpolation='bilinear')
        plt.axis('off')
        plt.title(title)
        plt.show()
    except ImportError:
        print("WordCloud not available. Install with: pip install wordcloud")

def validate_features_compatibility(extracted_features, model_features):
    """
    ✅ NEW: Validate feature compatibility between extracted and model features
    """
    missing_features = [f for f in model_features if f not in extracted_features.index]
    extra_features = [f for f in extracted_features.index if f not in model_features]
    
    if missing_features or extra_features:
        print(f"⚠️ Feature mismatch detected:")
        if missing_features:
            print(f"   Missing: {missing_features}")
        if extra_features:
            print(f"   Extra: {extra_features}")
        return False
    
    print("✅ Features compatible!")
    return True

def create_balanced_test_dataset():
    """
    ✅ NEW: Create balanced dataset with real-world URLs for testing
    """
    test_urls = [
        # Simple benign URLs
        ('https://google.com', 'benign'),
        ('https://facebook.com', 'benign'),
        ('https://amazon.com', 'benign'),
        ('https://microsoft.com', 'benign'),
        ('https://netflix.com', 'benign'),
        ('https://github.com', 'benign'),
        ('https://linkedin.com', 'benign'),
        
        # Obvious phishing URLs
        ('http://google-account-suspended.tk', 'phishing'),
        ('http://paypal-verify-immediately.fake.com', 'phishing'),
        ('http://amazon-security-alert.ml', 'phishing'),
        ('http://microsoft-update-required.suspicious.com', 'phishing'),
        ('http://urgent-account-verification.scam.org', 'phishing'),
        ('http://payp4l-security.fake.net', 'phishing'),
        ('http://g00gle-login.malicious.tk', 'phishing'),
    ]
    
    return pd.DataFrame(test_urls, columns=['url', 'type'])

# ============================================
# EXAMPLE USAGE
# ============================================

if __name__ == "__main__":
    print("🧪 Testing SecureME Enhanced Utils")
    print("=" * 50)
    
    # Test URL features
    test_url = "http://paypal-verify-account.fake.com/login"
    url_features = extract_features(test_url)
    print(f"📊 URL Features extracted: {len(url_features)}")
    print(f"🎯 Levenshtein distance: {url_features['levenshtein_min']}")
    print(f"🔍 Suspicious word count: {url_features['suspicious_word_count']}")
    
    # Test email features
    test_email = "URGENT: Your account will be suspended! Click here: http://fake-site.com"
    email_features = extract_email_features(test_email, "URGENT!", "fake@fake.com")
    print(f"\n📧 Email Features extracted: {len(email_features)}")
    print(f"🎯 URLs count: {email_features['urls']}")
    
    # Test production classifiers
    url_result = classify_url_production(test_url)
    print(f"\n🌐 URL Classification: {url_result}")
    
    email_result = classify_email_production(test_email, "URGENT!", "fake@fake.com")
    print(f"📧 Email Classification: {email_result}")
    
    print("\n✅ All tests completed!")