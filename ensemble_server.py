#!/usr/bin/env python3
"""
🚀 ENSEMBLE SERVER FINAL cu JSON ERROR HANDLING
Server HTTP pentru Phishing Detector Chrome Extension
30% RandomForest + 70% Hibrid
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import traceback
import json
from datetime import datetime

# Importă funcțiile din utils.py
try:
    from utils import ensemble_predict_email, load_randomforest_model, predict_with_randomforest, make_json_serializable
    print("✅ Successfully imported from utils.py")
except ImportError as e:
    print(f"❌ Failed to import from utils.py: {e}")
    print("📝 Make sure utils.py is in the same directory!")
    sys.exit(1)

# Creează aplicația Flask cu JSON config
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False  # Păstrează ordinea keys
CORS(app)  # Permite requests din Chrome extension

# Variabile globale
rf_model = None
server_start_time = datetime.now()

# ============================================
# JSON SERIALIZATION CUSTOM ENCODER
# ============================================

class NumpyJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder care gestionează numpy types"""
    def default(self, obj):
        import numpy as np
        if isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyJSONEncoder, self).default(obj)

app.json_encoder = NumpyJSONEncoder

# ============================================
# SAFE JSON RESPONSE HELPER
# ============================================

def safe_jsonify(data):
    """
    Convertește data la JSON în mod sigur, handling all edge cases
    """
    try:
        # Încearcă să convertească la JSON serializable
        safe_data = make_json_serializable(data)
        
        # Test că se poate serializa
        json.dumps(safe_data)
        
        return jsonify(safe_data)
        
    except Exception as e:
        print(f"❌ JSON serialization error: {e}")
        
        # Fallback la un răspuns minimal safe
        fallback_response = {
            'error': 'JSON serialization failed',
            'isPhishing': False,
            'score': 0.0,
            'reasons': ['Eroare tehnică în analiză'],
            'method': 'json_error_fallback'
        }
        
        return jsonify(fallback_response)

# ============================================
# STARTUP - ÎNCARCĂ MODELUL
# ============================================

print("🤖 Loading RandomForest model at startup...")
rf_model = load_randomforest_model()

if rf_model:
    print("✅ RandomForest model loaded successfully!")
else:
    print("⚠️ RandomForest model not found - using hybrid algorithm only")

print("🎯 Ensemble weights: 30% RandomForest + 70% Hibrid")

# ============================================
# API ENDPOINTS
# ============================================

@app.route('/', methods=['GET'])
def home():
    """Info page"""
    return """
    🎯 Phishing Detector Ensemble Server
    
    Endpoints:
    - GET  /health        - Server status
    - POST /analyze-email - Analyze email (for extension)
    - POST /analyze-rf    - RandomForest only (for testing)
    - GET  /test          - Run test examples
    
    Example:
    curl -X POST http://localhost:5000/analyze-email \\
         -H "Content-Type: application/json" \\
         -d '{"subject":"URGENT!","body":"Click here!","sender":"fake@fake.com"}'
    """

@app.route('/health', methods=['GET'])
def health_check():
    """Verifică starea serverului"""
    uptime = datetime.now() - server_start_time
    
    health_data = {
        'status': 'healthy',
        'server': 'Phishing Detector Ensemble',
        'rf_model_loaded': rf_model is not None,
        'ensemble_weights': '30% RandomForest + 70% Hibrid',
        'uptime_seconds': int(uptime.total_seconds()),
        'timestamp': datetime.now().isoformat()
    }
    
    return safe_jsonify(health_data)

@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    """
    🎯 ENDPOINT PRINCIPAL pentru extensia Chrome
    
    Input JSON:
    {
        "subject": "Email subject",
        "body": "Email body content",
        "sender": "sender@domain.com",
        "links": ["http://example.com"]
    }
    
    Output JSON:
    {
        "isPhishing": true/false,
        "score": 0.85,
        "reasons": ["reason1", "reason2"],
        "method": "ensemble_30%_rf_70%_hibrid",
        "breakdown": {...}
    }
    """
    try:
        # Validează input
        email_data = request.get_json()
        
        if not email_data:
            error_response = {
                'error': 'No email data provided',
                'isPhishing': False,
                'score': 0.0,
                'reasons': ['Invalid input'],
                'method': 'error'
            }
            return safe_jsonify(error_response), 400
        
        # Log request (safely)
        subject_preview = str(email_data.get('subject', ''))[:50]
        print(f"📨 Analyzing email: subject='{subject_preview}...'")
        
        # Apelează funcția ensemble
        result = ensemble_predict_email(email_data, alfa=0.3)
        
        # Log result (safely)
        method = result.get('method', 'unknown')
        score = result.get('score', 0.0)
        print(f"✅ Analysis complete: {method} = {score:.3f}")
        
        # Returnează cu safe JSON encoding
        return safe_jsonify(result)
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Analysis error: {error_msg}")
        traceback.print_exc()
        
        error_response = {
            'error': error_msg,
            'isPhishing': False,
            'score': 0.0,
            'reasons': [f'Server error: {error_msg}'],
            'method': 'error'
        }
        
        return safe_jsonify(error_response), 500

@app.route('/analyze-rf', methods=['POST'])
def analyze_randomforest_only():
    """
    🤖 Doar RandomForest (pentru testing)
    
    Returnează doar scorul RandomForest fără hibrid
    """
    try:
        email_data = request.get_json()
        
        if not email_data:
            return safe_jsonify({'error': 'No email data provided'}), 400
        
        # Doar RandomForest
        rf_score, rf_confidence = predict_with_randomforest(
            email_data.get('body', ''),
            email_data.get('subject', ''),
            email_data.get('sender', '')
        )
        
        result = {
            'score': float(rf_score),
            'confidence': float(rf_confidence),
            'method': 'randomforest_only',
            'model_loaded': rf_model is not None,
            'prediction': 'phishing' if rf_score > 0.5 else 'legitimate'
        }
        
        print(f"🤖 RandomForest only: {rf_score:.3f} (conf: {rf_confidence:.3f})")
        
        return safe_jsonify(result)
        
    except Exception as e:
        print(f"❌ RandomForest error: {e}")
        error_response = {
            'score': 0.5,
            'confidence': 0.0,
            'method': 'randomforest_error',
            'error': str(e)
        }
        return safe_jsonify(error_response), 500

@app.route('/test', methods=['GET'])
def test_examples():
    """🧪 Testează cu exemple predefinite"""
    
    test_emails = [
        {
            'subject': 'URGENT: Account Suspended!',
            'body': 'Your PayPal account suspended! Click here: http://paypal-fake.com',
            'sender': 'security@paypal-fake.com',
            'links': ['http://paypal-fake.com'],
            'description': 'Obvious phishing'
        },
        {
            'subject': 'Pull Request Merged',
            'body': 'Your GitHub pull request has been merged successfully.',
            'sender': 'notifications@github.com',
            'links': ['https://github.com/user/repo'],
            'description': 'Legitimate notification'
        },
        {
            'subject': 'You Won $10,000!',
            'body': 'Congratulations! Claim your prize: http://lottery-scam.tk',
            'sender': 'winner@fake-lottery.org',
            'links': ['http://lottery-scam.tk'],
            'description': 'Lottery scam'
        }
    ]
    
    results = []
    for email_test in test_emails:
        try:
            result = ensemble_predict_email(email_test, alfa=0.3)
            
            # Simplificat pentru test response
            test_result = {
                'description': email_test['description'],
                'input': {
                    'subject': email_test['subject'],
                    'sender': email_test['sender']
                },
                'result': {
                    'isPhishing': bool(result.get('isPhishing', False)),
                    'score': float(result.get('score', 0.0)),
                    'method': str(result.get('method', 'unknown')),
                    'reasons': [str(r) for r in result.get('reasons', [])[:2]]
                }
            }
            
            results.append(test_result)
            
        except Exception as e:
            results.append({
                'description': email_test['description'],
                'error': str(e)
            })
    
    response_data = {
        'test_results': results,
        'server_info': {
            'rf_model_loaded': rf_model is not None,
            'ensemble_formula': '30% RandomForest + 70% Hibrid',
            'total_tests': len(test_emails)
        }
    }
    
    return safe_jsonify(response_data)

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    error_response = {
        'error': 'Endpoint not found',
        'available_endpoints': ['/', '/health', '/analyze-email', '/analyze-rf', '/test']
    }
    return safe_jsonify(error_response), 404

@app.errorhandler(500)
def internal_error(error):
    error_response = {
        'error': 'Internal server error',
        'message': 'Check server logs for details'
    }
    return safe_jsonify(error_response), 500

# ============================================
# MAIN STARTUP
# ============================================

def main():
    """Pornește serverul cu configurațiile optime"""
    
    print("🚀 Starting Phishing Detector Ensemble Server...")
    print("-" * 60)
    print(f"🤖 RandomForest model: {'✅ Loaded' if rf_model else '❌ Not available'}")
    print(f"🔄 Hybrid algorithm: ✅ Active")
    print(f"🎯 Ensemble formula: 30% RandomForest + 70% Hibrid")
    print(f"🔧 JSON serialization: ✅ Fixed")
    print(f"📡 Server URL: http://127.0.0.1:5000")
    print(f"🧪 Test endpoint: http://127.0.0.1:5000/test")
    print(f"❤️ Health check: http://127.0.0.1:5000/health")
    print("-" * 60)
    print(f"🌐 Ready for Chrome extension requests!")
    print(f"⏹️ Press Ctrl+C to stop the server")
    print("-" * 60)
    
    # Pornește serverul
    try:
        app.run(
            host='127.0.0.1',  # Doar local
            port=5000,          # Port standard
            debug=False,        # Fără debug în producție
            threaded=True       # Multi-threading pentru multiple requests
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server error: {e}")

if __name__ == '__main__':
    main()