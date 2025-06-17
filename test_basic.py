#!/usr/bin/env python3
"""
🧪 TEST BASIC - fără requests
Testează doar funcțiile core din utils.py
"""

import sys
import os

def test_utils_import():
    """Test import utils.py"""
    print("1. 📦 Testing utils.py import...")
    
    try:
        from utils import (
            extract_email_features, 
            predict_with_randomforest, 
            detect_phishing_hybrid,
            ensemble_predict_email,
            load_randomforest_model
        )
        print("   ✅ All functions imported successfully")
        return True
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")
        return False

def test_email_features():
    """Test feature extraction"""
    print("\n2. 📧 Testing email feature extraction...")
    
    try:
        from utils import extract_email_features
        
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
        
        print(f"   ✅ Extracted {len(features)} features")
        print(f"   📊 Sample: {dict(list(features.items())[:3])}")
        
        if len(features) == 16:
            print("   ✅ Correct number of features (16)")
            return True
        else:
            print(f"   ⚠️ Expected 16 features, got {len(features)}")
            return False
            
    except Exception as e:
        print(f"   ❌ Feature extraction failed: {e}")
        return False

def test_randomforest_model():
    """Test RandomForest model"""
    print("\n3. 🤖 Testing RandomForest model...")
    
    try:
        from utils import load_randomforest_model, predict_with_randomforest
        
        model = load_randomforest_model()
        
        if model is not None:
            print(f"   ✅ Model loaded: {type(model)}")
        else:
            print("   ⚠️ No model found - will use adaptive approach")
        
        # Test prediction
        score, confidence = predict_with_randomforest(
            "URGENT: Click here now!",
            "URGENT!",
            "fake@fake.com"
        )
        
        print(f"   🎯 Prediction: score={score:.3f}, confidence={confidence:.3f}")
        
        if 0 <= score <= 1 and 0 <= confidence <= 1:
            print("   ✅ Valid prediction range")
            return True
        else:
            print("   ❌ Invalid prediction range")
            return False
            
    except Exception as e:
        print(f"   ❌ RandomForest test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_hybrid_algorithm():
    """Test hybrid algorithm"""
    print("\n4. 🔄 Testing hybrid algorithm...")
    
    try:
        from utils import detect_phishing_hybrid
        
        # Test phishing email
        phishing_email = {
            'subject': 'URGENT: Account Suspended!',
            'body': 'Your PayPal account suspended! Click here: http://fake-site.com',
            'sender': 'fake@fake.com',
            'links': ['http://fake-site.com']
        }
        
        score1, reasons1 = detect_phishing_hybrid(phishing_email)
        print(f"   📧 Phishing test: score={score1:.3f}, reasons={len(reasons1)}")
        
        # Test legitimate email
        legit_email = {
            'subject': 'Newsletter',
            'body': 'Thank you for subscribing.',
            'sender': 'newsletter@company.com',
            'links': ['https://company.com']
        }
        
        score2, reasons2 = detect_phishing_hybrid(legit_email)
        print(f"   📧 Legit test: score={score2:.3f}, reasons={len(reasons2)}")
        
        # Verifică că phishing are scor mai mare
        if score1 > score2:
            print("   ✅ Phishing scored higher than legitimate")
            return True
        else:
            print("   ⚠️ Unexpected scoring pattern")
            return False
            
    except Exception as e:
        print(f"   ❌ Hybrid test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ensemble_system():
    """Test ensemble system"""
    print("\n5. 🎯 Testing ensemble system...")
    
    try:
        from utils import ensemble_predict_email
        
        test_email = {
            'subject': 'URGENT: Verify Account!',
            'body': 'Your account will be suspended! Click: http://fake-site.com',
            'sender': 'security@fake.com',
            'links': ['http://fake-site.com']
        }
        
        result = ensemble_predict_email(test_email, alfa=0.3)
        
        print(f"   ✅ Ensemble result:")
        print(f"      Method: {result['method']}")
        print(f"      Score: {result['score']:.3f}")
        print(f"      Is phishing: {result['isPhishing']}")
        print(f"      Reasons: {len(result['reasons'])}")
        
        if 'breakdown' in result:
            print(f"      Formula: {result['breakdown']['formula']}")
        
        # Verifică structura
        required_keys = ['isPhishing', 'score', 'reasons', 'method', 'breakdown']
        if all(key in result for key in required_keys):
            print("   ✅ Valid result structure")
            return True
        else:
            print("   ❌ Invalid result structure")
            return False
            
    except Exception as e:
        print(f"   ❌ Ensemble test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run basic tests"""
    
    print("🧪 BASIC INTEGRATION TESTS (No Network)")
    print("=" * 50)
    
    tests = [
        test_utils_import,
        test_email_features,
        test_randomforest_model,
        test_hybrid_algorithm,
        test_ensemble_system
    ]
    
    results = []
    
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"   ❌ Test crashed: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 SUMMARY")
    print("=" * 50)
    
    test_names = [
        "Utils Import",
        "Email Features", 
        "RandomForest",
        "Hybrid Algorithm",
        "Ensemble System"
    ]
    
    passed = sum(results)
    total = len(results)
    
    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{i+1}. {name:<20} {status}")
    
    print(f"\n📊 RESULT: {passed}/{total} tests passed ({passed/total:.1%})")
    
    if passed >= 4:  # 4/5 tests should pass
        print("🎉 CORE SYSTEM WORKING!")
        print("\n🚀 Next steps:")
        print("   1. Install full dependencies: pip install requests flask flask-cors")
        print("   2. Start server: python ensemble_server.py") 
        print("   3. Or use: python start_system.py")
    else:
        print("❌ CORE SYSTEM ISSUES - Check utils.py")
    
    return passed >= 4

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)