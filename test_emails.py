#!/usr/bin/env python3
"""
🧪 TEST EMAILS SIMULATION
Testează sistemul cu emailuri realiste de phishing vs legitime
"""

import requests
import json

# URL-ul serverului
SERVER_URL = 'http://127.0.0.1:5000'

def test_email(email_data, description):
    """Testează un email și afișează rezultatul"""
    print(f"\n📧 {description}")
    print("-" * 60)
    print(f"📬 Subject: {email_data['subject']}")
    print(f"👤 Sender: {email_data['sender']}")
    print(f"📝 Body: {email_data['body'][:100]}...")
    
    try:
        response = requests.post(
            f'{SERVER_URL}/analyze-email',
            json=email_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Determină culoarea pentru rezultat
            if result['isPhishing']:
                status_icon = "🚨 PHISHING DETECTED"
                color = "RED"
            else:
                status_icon = "✅ SAFE EMAIL"
                color = "GREEN"
            
            print(f"\n{status_icon}")
            print(f"📊 Score: {result['score']:.3f}/1.0")
            print(f"🎯 Method: {result['method']}")
            print(f"📝 Reasons:")
            
            for i, reason in enumerate(result['reasons'][:3], 1):
                print(f"   {i}. {reason}")
            
            if 'breakdown' in result:
                print(f"\n🔧 Breakdown:")
                print(f"   🤖 RandomForest: {result['breakdown']['rf_score']:.3f}")
                print(f"   🔄 Hibrid: {result['breakdown']['hibrid_score']:.3f}")
                print(f"   ⚖️ Formula: {result['breakdown']['formula']}")
            
            return result['isPhishing'], result['score']
            
        else:
            print(f"❌ Server error: {response.status_code}")
            return None, None
            
    except requests.exceptions.ConnectionError:
        print("❌ Server not running! Start with: python ensemble_server.py")
        return None, None
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return None, None

def main():
    """Rulează testele cu emailuri simulate"""
    
    print("🧪 EMAIL PHISHING DETECTION SIMULATION")
    print("=" * 70)
    
    # Test 1: EMAIL PHISHING CLASIC
    phishing_email = {
        'subject': 'URGENT: Your PayPal Account Has Been Limited',
        'body': '''Dear Customer,
        
We have detected suspicious activity on your PayPal account and have temporarily limited access to protect you.

IMMEDIATE ACTION REQUIRED:
• Your account will be permanently suspended in 24 hours
• Click here to verify your identity: http://paypal-verification.secure-login.tk
• Failure to verify will result in account closure

This is an automated security measure. Please do not reply to this email.

Thanks,
PayPal Security Team''',
        'sender': 'security@paypal-service.info',
        'links': ['http://paypal-verification.secure-login.tk']
    }
    
    # Test 2: EMAIL LEGITIM
    legitimate_email = {
        'subject': 'Your GitHub pull request has been merged',
        'body': '''Hi there!

Your pull request #456 "Fix authentication bug" has been successfully merged into the main branch.

Details:
• Repository: user/awesome-project
• Merged by: maintainer
• View changes: https://github.com/user/awesome-project/pull/456

You can view the merged changes and continue contributing to the project.

Happy coding!
GitHub Team''',
        'sender': 'notifications@github.com',
        'links': ['https://github.com/user/awesome-project/pull/456']
    }
    
    # Test 3: EMAIL PHISHING SUBTIL (mai greu de detectat)
    subtle_phishing = {
        'subject': 'Important: Update your payment information',
        'body': '''Hello,
        
Your recent payment for Microsoft Office 365 could not be processed. Please update your payment information to avoid service interruption.

Update payment method: https://microsoft-billing.secure-updates.com/payment

If you don't update within 3 days, your subscription will be canceled.

Best regards,
Microsoft Billing Team''',
        'sender': 'billing@microsoft-services.com',
        'links': ['https://microsoft-billing.secure-updates.com/payment']
    }
    
    # Rulează testele
    results = []
    
    # Test phishing clasic
    is_phishing_1, score_1 = test_email(phishing_email, "TEST 1: PHISHING CLASIC PayPal")
    results.append(('Phishing Classic', is_phishing_1, score_1, True))  # True = should be detected
    
    # Test legitim
    is_phishing_2, score_2 = test_email(legitimate_email, "TEST 2: EMAIL LEGITIM GitHub")
    results.append(('Legitimate GitHub', is_phishing_2, score_2, False))  # False = should be safe
    
    # Test phishing subtil
    is_phishing_3, score_3 = test_email(subtle_phishing, "TEST 3: PHISHING SUBTIL Microsoft")
    results.append(('Phishing Subtle', is_phishing_3, score_3, True))  # True = should be detected
    
    # Raport final
    print("\n" + "=" * 70)
    print("📋 DETECTION SUMMARY")
    print("=" * 70)
    
    correct_predictions = 0
    total_tests = 0
    
    for test_name, detected, score, should_detect in results:
        if detected is not None and score is not None:
            total_tests += 1
            
            if detected == should_detect:
                result_icon = "✅ CORRECT"
                correct_predictions += 1
            else:
                result_icon = "❌ WRONG"
            
            expected = "PHISHING" if should_detect else "SAFE"
            actual = "PHISHING" if detected else "SAFE"
            
            print(f"{test_name:<20} | Score: {score:.3f} | Expected: {expected:<8} | Got: {actual:<8} | {result_icon}")
    
    if total_tests > 0:
        accuracy = correct_predictions / total_tests
        print(f"\n📊 ACCURACY: {correct_predictions}/{total_tests} ({accuracy:.1%})")
        
        if accuracy >= 0.7:
            print("🎉 EXCELLENT! System is working well!")
        elif accuracy >= 0.5:
            print("👍 GOOD! System needs minor tuning")
        else:
            print("⚠️ NEEDS IMPROVEMENT! Check threshold settings")
    
    print("\n💡 TIPS:")
    print("   • Score 0.0-0.3: Very safe")
    print("   • Score 0.3-0.5: Probably safe") 
    print("   • Score 0.5-0.7: Suspicious")
    print("   • Score 0.7-1.0: High phishing risk")

if __name__ == "__main__":
    main()