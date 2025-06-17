#!/usr/bin/env python3
"""
🧪 TEST INTEGRATION FINAL
Testează întregul sistem: utils.py + ensemble_server.py + background.js
"""

import sys
import os
import time
import subprocess
import requests
from datetime import datetime

# ============================================
# FUNCȚII DE TESTARE
# ============================================

def test_utils_import():
    """Test 1: Verifică dacă se poate importa utils.py"""
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
    """Test 2: Verifică extragerea de features"""
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
        print(f"   📊 Sample features: {dict(list(features.items())[:3])}")
        
        # Verifică că are exact 16 features
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
    """Test 3: Verifică încărcarea modelului RandomForest"""
    print("\n3. 🤖 Testing RandomForest model...")
    
    try:
        from utils import load_randomforest_model, predict_with_randomforest
        
        # Încarcă modelul
        model = load_randomforest_model()
        
        if model is not None:
            print(f"   ✅ Model loaded: {type(model)}")
            
            # Test predicție
            score, confidence = predict_with_randomforest(
                "URGENT: Click here now!",
                "URGENT!",
                "fake@fake.com"
            )
            
            print(f"   🎯 Test prediction: score={score:.3f}, confidence={confidence:.3f}")
            
            if 0 <= score <= 1 and 0 <= confidence <= 1:
                print("   ✅ Valid prediction scores")
                return True
            else:
                print("   ⚠️ Invalid prediction scores")
                return False
        else:
            print("   ⚠️ RandomForest model not found - will use adaptive approach")
            
            # Test cu adaptive approach
            score, confidence = predict_with_randomforest(
                "URGENT: Click here now!",
                "URGENT!",
                "fake@fake.com"
            )
            
            print(f"   🔧 Adaptive prediction: score={score:.3f}, confidence={confidence:.3f}")
            return True
            
    except Exception as e:
        print(f"   ❌ RandomForest test failed: {e}")
        return False

def test_hybrid_algorithm():
    """Test 4: Verifică algoritmul hibrid"""
    print("\n4. 🔄 Testing hybrid algorithm...")
    
    try:
        from utils import detect_phishing_hybrid
        
        test_cases = [
            {
                'subject': 'URGENT: Account Suspended!',
                'body': 'Your account suspended! Click here: http://fake-site.com',
                'sender': 'fake@fake.com',
                'links': ['http://fake-site.com'],
                'expected_high': True  # Ar trebui să aibă scor mare
            },
            {
                'subject': 'Newsletter',
                'body': 'Thank you for subscribing to our newsletter.',
                'sender': 'newsletter@company.com',
                'links': ['https://company.com'],
                'expected_high': False  # Ar trebui să aibă scor mic
            }
        ]
        
        all_passed = True
        
        for i, test_case in enumerate(test_cases):
            score, reasons = detect_phishing_hybrid(test_case)
            
            print(f"   📧 Test {i+1}: score={score:.3f}, reasons={len(reasons)}")
            
            if test_case['expected_high'] and score > 0.3:
                print(f"      ✅ High score as expected")
            elif not test_case['expected_high'] and score < 0.5:
                print(f"      ✅ Low score as expected")
            else:
                print(f"      ⚠️ Unexpected score")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"   ❌ Hybrid algorithm test failed: {e}")
        return False

def test_ensemble_system():
    """Test 5: Verifică sistemul ensemble"""
    print("\n5. 🎯 Testing ensemble system...")
    
    try:
        from utils import ensemble_predict_email
        
        test_email = {
            'subject': 'URGENT: Verify Account!',
            'body': 'Your PayPal account will be suspended! Click here: http://fake-paypal.com',
            'sender': 'security@fake-paypal.com',
            'links': ['http://fake-paypal.com']
        }
        
        result = ensemble_predict_email(test_email, alfa=0.3)
        
        print(f"   ✅ Ensemble result: {result['method']}")
        print(f"   📊 Score: {result['score']:.3f}")
        print(f"   🎯 Is phishing: {result['isPhishing']}")
        print(f"   📝 Reasons: {len(result['reasons'])}")
        print(f"   🔧 Formula: {result['breakdown']['formula']}")
        
        # Verifică structura rezultatului
        required_keys = ['isPhishing', 'score', 'reasons', 'method', 'breakdown']
        if all(key in result for key in required_keys):
            print("   ✅ Valid result structure")
            return True
        else:
            print("   ❌ Invalid result structure")
            return False
            
    except Exception as e:
        print(f"   ❌ Ensemble test failed: {e}")
        return False

def test_server_functionality():
    """Test 6: Verifică dacă serverul poate fi pornit și răspunde"""
    print("\n6. 🌐 Testing server functionality...")
    
    try:
        # Încearcă să contacteze serverul dacă rulează
        response = requests.get('http://127.0.0.1:5000/health', timeout=3)
        
        if response.status_code == 200:
            health = response.json()
            print(f"   ✅ Server is running!")
            print(f"   📊 Status: {health.get('status', 'unknown')}")
            print(f"   🤖 RF model: {'✅' if health.get('rf_model_loaded') else '❌'}")
            
            # Test analyze endpoint
            test_data = {
                'subject': 'Test',
                'body': 'Test email',
                'sender': 'test@test.com',
                'links': []
            }
            
            analyze_response = requests.post(
                'http://127.0.0.1:5000/analyze-email',
                json=test_data,
                timeout=5
            )
            
            if analyze_response.status_code == 200:
                result = analyze_response.json()
                print(f"   ✅ Analysis endpoint working")
                print(f"   📊 Method: {result.get('method', 'unknown')}")
                return True
            else:
                print(f"   ❌ Analysis endpoint failed: {analyze_response.status_code}")
                return False
        else:
            print(f"   ❌ Server health check failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("   ⚠️ Server not running - start with: python ensemble_server.py")
        return False
    except Exception as e:
        print(f"   ❌ Server test failed: {e}")
        return False

def test_complete_workflow():
    """Test 7: Workflow complet ca extensia Chrome"""
    print("\n7. 🔄 Testing complete workflow...")
    
    try:
        from utils import ensemble_predict_email
        
        # Simulează email-uri ca din extensie
        workflow_tests = [
            {
                'name': 'Phishing PayPal',
                'data': {
                    'subject': 'Action Required: Verify Your PayPal Account',
                    'body': 'URGENT: Your PayPal account has been limited. Verify immediately: http://paypal-verify.fake.com',
                    'sender': 'service@paypal-secure.info',
                    'links': ['http://paypal-verify.fake.com']
                },
                'expected': 'phishing'
            },
            {
                'name': 'Legitimate GitHub',
                'data': {
                    'subject': 'Pull Request Merged',
                    'body': 'Your pull request #123 has been successfully merged.',
                    'sender': 'notifications@github.com',
                    'links': ['https://github.com/user/repo/pull/123']
                },
                'expected': 'legitimate'
            },
            {
                'name': 'Lottery Scam',
                'data': {
                    'subject': 'CONGRATULATIONS! You Won $50,000!',
                    'body': 'You are the lucky winner! Claim your prize now: http://lottery-win.tk',
                    'sender': 'winner@international-lottery.org',
                    'links': ['http://lottery-win.tk']
                },
                'expected': 'phishing'
            }
        ]
        
        results = []
        
        for test in workflow_tests:
            print(f"   📧 Testing: {test['name']}")
            
            result = ensemble_predict_email(test['data'])
            
            prediction = 'phishing' if result['isPhishing'] else 'legitimate'
            correct = prediction == test['expected']
            
            results.append(correct)
            
            status = "✅" if correct else "⚠️"
            print(f"      {status} Expected: {test['expected']}, Got: {prediction} (score: {result['score']:.3f})")
        
        accuracy = sum(results) / len(results)
        print(f"   📊 Workflow accuracy: {accuracy:.1%}")
        
        return accuracy >= 0.5  # Cel puțin 50% accuracy
        
    except Exception as e:
        print(f"   ❌ Workflow test failed: {e}")
        return False

# ============================================
# MAIN TEST RUNNER
# ============================================

def main():
    """Rulează toate testele și afișează raportul final"""
    
    print("🧪 PHISHING DETECTOR - INTEGRATION TESTS")
    print("=" * 60)
    print(f"⏰ Started at: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    
    # Lista testelor
    tests = [
        test_utils_import,
        test_email_features,
        test_randomforest_model,
        test_hybrid_algorithm,
        test_ensemble_system,
        test_server_functionality,
        test_complete_workflow
    ]
    
    # Rulează testele
    results = []
    
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"   ❌ Test crashed: {e}")
            results.append(False)
    
    # Raport final
    print("\n" + "=" * 60)
    print("📋 FINAL REPORT")
    print("=" * 60)
    
    test_names = [
        "Utils Import",
        "Email Features", 
        "RandomForest Model",
        "Hybrid Algorithm",
        "Ensemble System",
        "Server Functionality",
        "Complete Workflow"
    ]
    
    passed = sum(results)
    total = len(results)
    
    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{i+1}. {name:<20} {status}")
    
    print("-" * 60)
    print(f"📊 SUMMARY: {passed}/{total} tests passed ({passed/total:.1%})")
    
    if passed >= 5:  # Cel puțin 5/7 teste trebuie să treacă
        print("🎉 SYSTEM READY!")
        print("\n🚀 Next steps:")
        print("   1. Start server: python ensemble_server.py")
        print("   2. Load Chrome extension (chrome://extensions/)")
        print("   3. Test on Gmail!")
    else:
        print("❌ SYSTEM NOT READY - Fix failing tests first")
        
        if not results[0]:  # Utils import failed
            print("💡 Fix: Check utils.py file")
        if not results[5]:  # Server failed
            print("💡 Fix: Start server with: python ensemble_server.py")
    
    print("=" * 60)
    return passed >= 5

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)