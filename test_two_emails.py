#!/usr/bin/env python3
"""
🧪 TEST TWO EMAILS - Testează detectarea pe emailuri contrastante
Un email evident phishing vs un email legitim
"""

import requests
import json
from datetime import datetime

def test_email(email_data, description, expected_result):
    """
    Testează un email cu serverul
    
    Args:
        email_data: dict cu subject, body, sender, links
        description: string descrierea testului
        expected_result: 'phishing' sau 'legitimate'
    """
    
    print(f"\n📧 {description}")
    print("=" * 60)
    print(f"📬 Subject: '{email_data['subject']}'")
    print(f"👤 Sender: '{email_data['sender']}'")
    print(f"📝 Body: {email_data['body'][:100]}{'...' if len(email_data['body']) > 100 else ''}")
    print(f"🔗 Links: {len(email_data.get('links', []))} link(s)")
    print(f"🎯 Expected: {expected_result.upper()}")
    
    try:
        # Test cu serverul
        response = requests.post(
            "http://localhost:5000/analyze-email",
            json=email_data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Analiză rezultat
            actual = 'phishing' if result['isPhishing'] else 'legitimate'
            is_correct = actual == expected_result
            
            # Afișare rezultat
            status_icon = "✅" if is_correct else "❌"
            warning_icon = "🚨" if result['isPhishing'] else "✅"
            
            print(f"\n{warning_icon} RESULT: {actual.upper()} (score: {result['score']:.3f}) {status_icon}")
            print(f"🎚️ Threshold: {result['breakdown'].get('threshold', 'unknown')}")
            print(f"🔧 Method: {result['method']}")
            print(f"📐 Formula: {result['breakdown'].get('formula', 'unknown')}")
            
            # Breakdown detaliat
            print(f"\n🔧 BREAKDOWN:")
            print(f"   🤖 RandomForest: {result['breakdown']['rf_score']:.3f}")
            print(f"   🔄 Hibrid: {result['breakdown']['hibrid_score']:.3f}")
            print(f"   ⚖️ Weights: {result['breakdown']['weights']}")
            
            # Top 3 reasons
            print(f"\n📝 TOP REASONS:")
            for i, reason in enumerate(result['reasons'][:3], 1):
                print(f"   {i}. {reason}")
            
            # Evaluation
            if is_correct:
                if actual == 'phishing':
                    print(f"\n🎯 EXCELLENT! Phishing-ul a fost detectat corect!")
                else:
                    print(f"\n👍 GOOD! Email-ul legitim nu a fost marcat greșit!")
            else:
                if actual == 'phishing' and expected_result == 'legitimate':
                    print(f"\n⚠️ FALSE POSITIVE! Email legitim marcat ca phishing!")
                else:
                    print(f"\n⚠️ FALSE NEGATIVE! Phishing-ul nu a fost detectat!")
            
            return {
                'correct': is_correct,
                'actual': actual,
                'expected': expected_result,
                'score': result['score'],
                'is_phishing': result['isPhishing'],
                'reasons': result['reasons'],
                'breakdown': result['breakdown']
            }
            
        else:
            print(f"❌ Server error: {response.status_code}")
            print(f"Response: {response.text[:200]}...")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Server not running!")
        print("💡 Start server with: python ensemble_server.py")
        return None
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return None

def main():
    """Testează două emailuri contrastante"""
    
    print("🧪 TESTING TWO CONTRASTING EMAILS")
    print("=" * 70)
    print(f"⏰ Started at: {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 70)
    
    # EMAIL 1: PHISHING EVIDENT (PayPal fake)
    phishing_email = {
        "subject": "URGENT: Your PayPal Account Has Been Limited",
        "body": """Dear Customer,

We have detected suspicious activity on your PayPal account and have temporarily limited access to protect you.

IMMEDIATE ACTION REQUIRED:
• Your account will be permanently suspended in 24 hours
• Click here to verify your identity: http://paypal-verification.secure-login.tk
• Failure to verify will result in account closure

This is an automated security measure. Please do not reply to this email.

Thanks,
PayPal Security Team""",
        "sender": "security@paypal-service.info",
        "links": ["http://paypal-verification.secure-login.tk"]
    }
    
    # EMAIL 2: LEGITIM (GitHub notification)
    legitimate_email = {
        "subject": "Pull Request #456 has been merged",
        "body": """Hi there!

Your pull request #456 "Fix authentication bug" has been successfully merged into the main branch.

Details:
• Repository: user/awesome-project
• Merged by: project-maintainer
• View changes: https://github.com/user/awesome-project/pull/456

You can view the merged changes and continue contributing to the project. Thank you for your contribution!

Happy coding!
GitHub Team""",
        "sender": "notifications@github.com",
        "links": ["https://github.com/user/awesome-project/pull/456"]
    }
    
    # TESTEAZĂ AMBELE EMAILURI
    results = []
    
    # Test 1: Phishing email
    result1 = test_email(
        phishing_email,
        "TEST 1: PHISHING EVIDENT (PayPal fake)",
        "phishing"
    )
    results.append(result1)
    
    # Test 2: Legitimate email  
    result2 = test_email(
        legitimate_email,
        "TEST 2: EMAIL LEGITIM (GitHub notification)",
        "legitimate"
    )
    results.append(result2)
    
    # SUMMARY FINAL
    print("\n" + "=" * 70)
    print("📋 FINAL SUMMARY")
    print("=" * 70)
    
    if all(r is not None for r in results):
        correct_count = sum(1 for r in results if r['correct'])
        total_count = len(results)
        accuracy = correct_count / total_count
        
        print(f"📊 ACCURACY: {correct_count}/{total_count} ({accuracy:.1%})")
        
        # Detailed results
        test_names = ["PayPal Phishing", "GitHub Legitimate"]
        for i, (name, result) in enumerate(zip(test_names, results)):
            if result:
                status = "✅ CORRECT" if result['correct'] else "❌ WRONG"
                print(f"   {i+1}. {name:<20} | Score: {result['score']:.3f} | {result['actual'].upper():<10} | {status}")
        
        # Performance evaluation
        print(f"\n🎯 PERFORMANCE ANALYSIS:")
        
        if accuracy == 1.0:
            print("🎉 PERFECT! System correctly identified both emails!")
            print("✅ No false positives (legitimate emails marked as phishing)")
            print("✅ No false negatives (phishing emails missed)")
            
        elif accuracy >= 0.5:
            print("👍 GOOD! System performed reasonably well")
            
            # Analyze errors
            for i, result in enumerate(results):
                if result and not result['correct']:
                    if result['actual'] == 'phishing' and result['expected'] == 'legitimate':
                        print(f"⚠️ False positive detected in test {i+1}")
                    elif result['actual'] == 'legitimate' and result['expected'] == 'phishing':
                        print(f"⚠️ False negative detected in test {i+1}")
        else:
            print("⚠️ NEEDS IMPROVEMENT! System accuracy is low")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        if results[0] and results[0]['correct'] and results[1] and results[1]['correct']:
            print("🚀 System is ready for production!")
            print("📧 Can be safely used with Chrome extension")
            print("🎯 Excellent balance between detection and false positives")
            
        elif results[0] and not results[0]['correct']:
            print("🔧 Need to improve phishing detection sensitivity")
            print("💡 Consider lowering threshold or enhancing phishing patterns")
            
        elif results[1] and not results[1]['correct']:
            print("🔧 Need to reduce false positives")
            print("💡 Consider raising threshold or improving legitimate email recognition")
    
    else:
        print("❌ Some tests failed due to server issues")
        print("💡 Make sure server is running: python ensemble_server.py")
    
    print("=" * 70)

if __name__ == "__main__":
    main()