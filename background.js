// 🎯 PHISHING DETECTOR - BACKGROUND SCRIPT FINAL
// Păstrează COMPLET algoritmul original + adaugă ensemble cu Python server



const phishingKeywords = [
  'urgent', 'verify', 'banking', 'password', 'credit card', 'social security',
  'click', 'suspicious', 'required', 'limited', 'expire', 'paypal', 'atm', 
  'authenticate', 'validation', 'fraud', 'lottery', 'winning', 'prize', 'claim',
  'congrats', 'congratulation', 'gift', 'free', 'unexpected', 'inheritance', 
  'suspended', 'unauthorized', 'immediate', 'action', 'invoice',
  'limited time', 'offer', 'tax', 'refund', 'wire transfer', 'money',
  'bitcoin', 'crypto', 'investment', 'double', 'profit', 'beneficiary', 
  'identity', 'theft', 'compromise', 'hacked', 'restriction', 'disable', 
  'urgent', 'verifică', 'bancă', 'parolă', 'card de credit', 'securitate socială',
  'clic', 'suspect', 'necesar', 'limitat', 'expiră', 'plată', 'bancomat', 
  'autentificare', 'validare', 'fraudă', 'loterie', 'câștig', 'premiu', 'revendicare',
  'felicitări', 'cadou', 'gratuit', 'neașteptat', 'moștenire', 
  'suspendat', 'neautorizat', 'imediat', 'acțiune', 'factură',
  'timp limitat', 'ofertă', 'impozit', 'rambursare', 'transfer bancar', 'bani',
  'bitcoin', 'crypto', 'investiție', 'dublu', 'profit', 'beneficiar', 
  'identitate', 'furt', 'compromis', 'hacked', 'restricție', 'dezactivare'
];

const suspiciousDomains = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
  'buff.ly', 'adf.ly', 'tiny.cc', 'clck.ru', 'pixelme.me', 
  'cutt.ly', 'shorturl.at', 'rebrand.ly', 'j.mp', 'urly.co'
];

const financialServices = [
  'paypal', 'visa', 'mastercard', 'americanexpress', 'banking', 
  'bank', 'western union', 'moneygram', 'revolut', 'transferwise', 
  'stripe', 'square', 'citibank', 'hsbc', 'chase', 'wellsfargo'
];

const sensitivePatterns = [
  /enter.{1,20}(password|credentials)/i,
  /(confirm|update|verify).{1,20}(details|information)/i,
  /(credit\.?card|card\.?number)/i,
  /(social\.?security|SSN)/i,
  /(account\.?number|routing\.?number)/i,
  /(PIN|personal\.?identification\.?number)/i,
  /(username|user\.?id).{1,20}(and|&).{1,20}password/i,
  /bank.{1,30}(details|login|account)/i,
  /(tax|financial).{1,20}information/i
];

const urgencyPhrases = [
  'urgent', 'immediate', 'action required', 'alert', 'warning', 
  'critical', 'limited time', 'expire',
  'urgent', 'imediat', 'acțiune necesară', 'alertă', 'avertisment',
  'critic', 'timp limitat', 'expiră'
];

const trustedSenders = [
  "newsletter@company.com",
  "support@google.com",
  "no-reply@linkedin.com", 
  "info@amazon.com",
  "notifications@github.com",
  "news@medium.com",
  "noreply@youtube.com",
  "billing@microsoft.com"
];

/**
 * 🔄 FUNCȚIA TA ORIGINALĂ HIBRIDĂ (PĂSTRATĂ EXACT)
 * Detectează phishing folosind algoritmul original complet
 */
function detectPhishingWithAI(emailData) {
  const subject = emailData.subject || '';
  const body = emailData.body || '';
  const links = emailData.links || [];
  const sender = emailData.sender || '';
  
  // Verifică trusted senders
  if (trustedSenders.some(trusted => sender.toLowerCase().includes(trusted))) {
    console.log('Expeditor de încredere detectat:', sender);
    return {
      isPhishing: false,
      score: 0,
      reasons: ["Expeditor de încredere"],
      method: "hybrid_trusted"
    };
  }
  
  const text = subject + ' ' + body;
  const textLower = text.toLowerCase();
  
  let score = 0.0;
  const reasons = [];
  const debugInfo = {}; 
  
  // 1. Cuvinte cheie
  let keywordCount = 0;
  const keywordsDetected = [];
  
  for (const keyword of phishingKeywords) {
    if (textLower.includes(keyword)) {
      keywordCount++;
      keywordsDetected.push(keyword);
      if (keywordCount <= 3) { 
        reasons.push(`Email-ul conține cuvântul de alertă '${keyword}'`);
      }
    }
  }
  
  if (keywordCount > 0) {
    const keywordScore = Math.min(0.25, keywordCount * 0.05);
    score += keywordScore;
    debugInfo.keywordScore = keywordScore;
    debugInfo.keywordsDetected = keywordsDetected;
  }
  
  // 2. Link-uri suspecte
  let suspiciousLinkCount = 0;
  const suspiciousLinks = [];
  
  for (const link of links) {
    try {
      const domainMatch = link.match(/https?:\/\/([^\/]+)/);
      if (domainMatch) {
        const domain = domainMatch[1];
        if (suspiciousDomains.some(sd => domain.includes(sd))) {
          suspiciousLinkCount++;
          suspiciousLinks.push(domain);
          if (suspiciousLinkCount <= 2) { 
            reasons.push(`Link suspect: ${domain} (serviciu de scurtare URL)`);
          }
        }
      }
    } catch (error) {
      console.error("Eroare la procesarea link-ului:", error);
    }
  }
  
  if (suspiciousLinkCount > 0) {
    const linkScore = Math.min(0.3, suspiciousLinkCount * 0.15);
    score += linkScore;
    debugInfo.linkScore = linkScore;
    debugInfo.suspiciousLinks = suspiciousLinks;
  }
  
  // 3. Informații sensibile
  let sensitiveInfoDetected = false;
  
  for (const pattern of sensitivePatterns) {
    if (pattern.test(textLower)) {
      reasons.push("Email-ul solicită informații personale sau financiare sensibile");
      score += 0.3;
      sensitiveInfoDetected = true;
      debugInfo.sensitiveInfoScore = 0.3;
      break;
    }
  }

  // 4. Servicii financiare mismatch
  let misusedServiceDetected = false;
  let misusedService = '';
  
  for (const service of financialServices) {
    if (textLower.includes(service)) {
      let serviceLinkFound = false;
      for (const link of links) {
        if (link.toLowerCase().includes(service)) {
          serviceLinkFound = true;
          break;
        }
      }
      
      if (!serviceLinkFound && links.length > 0) {
        reasons.push(`Email-ul menționează '${service}' dar link-urile nu duc la site-ul oficial`);
        score += 0.3;
        misusedServiceDetected = true;
        misusedService = service;
        debugInfo.misusedServiceScore = 0.3;
        break;
      }
    }
  }

  // 5. Urgență
  let urgencyDetected = false;
  let urgencyPhrase = '';
  
  for (const phrase of urgencyPhrases) {
    if (textLower.includes(phrase)) {
      reasons.push("Email cu tonalitate urgentă pentru a grăbi acțiunea utilizatorului");
      score += 0.15; 
      urgencyDetected = true;
      urgencyPhrase = phrase;
      debugInfo.urgencyScore = 0.15;
      break;
    }
  }
  
  // 6. Pattern-uri phishing
  let patternMatchCount = 0;
  const patternMatches = [];
  
  const phishingPatterns = [
    /(we.{1,10}detected.{1,20}suspicious)/i,
    /(verify.{1,10}account.{1,10}prevent)/i,
    /(unusual.{1,10}activity)/i,
    /(security.{1,10}measure)/i,
    /(limited.{1,10}time.{1,10}offer)/i,
    /(click.{1,10}link.{1,10}below)/i,
    /(update.{1,10}information)/i,
    /(payment.{1,10}declined)/i,
    /(account.{1,10}suspended)/i,
    /(prize.{1,10}claim)/i
  ];
  
  for (const pattern of phishingPatterns) {
    if (pattern.test(text)) {
      patternMatchCount++;
      patternMatches.push(pattern.toString());
    }
  }
  
  if (patternMatchCount >= 2) {
    reasons.push("Analiza AI a detectat tipare lingvistice asociate cu phishing-ul");
    score += 0.2; 
    debugInfo.patternMatchScore = 0.2;
    debugInfo.patternMatches = patternMatches;
  }

  // Normalizează scorul
  score = Math.max(0, Math.min(1, score));
  const isPhishing = score > 0.7;
  
  if (reasons.length > 5) {
    reasons.splice(5);
  } else if (reasons.length === 0) {
    reasons.push("Nu am identificat motive specifice de îngrijorare.");
  }

  console.log('Analiză phishing hibrid (original):', {
    score: score,
    isPhishing: isPhishing,
    subject: subject,
    debug: debugInfo
  });
  
  return {
    isPhishing: isPhishing,
    score: score,
    reasons: reasons,
    method: "hybrid_algorithm_original",
    debugInfo: debugInfo
  };
}

// ============================================
// ENSEMBLE CU PYTHON SERVER (NOU)
// ============================================

const PYTHON_SERVER_URL = 'http://127.0.0.1:5000';

/**
 * 🎯 ENSEMBLE: Combină algoritmul original cu Python server
 * Dacă Python server e disponibil, folosește ensemble
 * Dacă nu, folosește doar algoritmul original
 */
async function detectPhishingWithEnsemble(emailData) {
  try {
    console.log('🎯 Attempting ensemble analysis...', emailData);
    
    // Încearcă să contacteze Python server-ul
    const response = await fetch(`${PYTHON_SERVER_URL}/analyze-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailData),
      timeout: 5000  // 5 secunde timeout
    });
    
    if (!response.ok) {
      throw new Error(`Server responded with status: ${response.status}`);
    }
    
    const ensembleResult = await response.json();
    console.log('✅ Ensemble result from Python server:', ensembleResult);
    
    // Convertește rezultatul pentru compatibilitate cu extensia
    return {
      isPhishing: ensembleResult.isPhishing,
      score: ensembleResult.score,
      reasons: ensembleResult.reasons,
      method: ensembleResult.method,
      breakdown: ensembleResult.breakdown
    };
    
  } catch (error) {
    console.warn('⚠️ Python server unavailable, using original hybrid algorithm:', error.message);
    
    // Fallback la algoritmul tău original
    const hybridResult = detectPhishingWithAI(emailData);
    hybridResult.method = 'hybrid_fallback_python_unavailable';
    hybridResult.note = 'Python server unavailable - using original algorithm';
    
    return hybridResult;
  }
}

/**
 * 🔍 Verifică dacă Python server-ul rulează
 */
async function checkPythonServerHealth() {
  try {
    const response = await fetch(`${PYTHON_SERVER_URL}/health`, {
      method: 'GET',
      timeout: 3000
    });
    
    if (response.ok) {
      const health = await response.json();
      console.log('🟢 Python server status:', health);
      return health;
    }
    
    throw new Error(`Health check failed: ${response.status}`);
    
  } catch (error) {
    console.log('🔴 Python server not available:', error.message);
    return null;
  }
}

// ============================================
// MESSAGE HANDLERS (PĂSTRAT DIN ORIGINAL)
// ============================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzeEmail') {
    console.log('📨 Received email analysis request:', message.data);
    
    // Folosește ensemble (cu fallback la hibrid original)
    detectPhishingWithEnsemble(message.data)
      .then(result => {
        // Salvează rezultatul pentru popup
        chrome.storage.local.set({ 
          lastAnalysis: {
            timestamp: Date.now(),
            data: message.data,
            result: result
          }
        });
        
        // Afișează warning dacă e phishing
        if (result.isPhishing) {
          chrome.tabs.sendMessage(sender.tab.id, {
            action: 'showWarning',
            isPhishing: result.isPhishing,
            score: result.score,
            reasons: result.reasons
          });
        }
        
        // Log pentru debugging
        console.log('📊 Final analysis result:', {
          method: result.method,
          score: result.score,
          isPhishing: result.isPhishing,
          pythonServerUsed: !result.method.includes('fallback')
        });
        
        sendResponse(result);
      })
      .catch(error => {
        console.error('❌ Critical error in analysis:', error);
        
        // Ultimate fallback la algoritmul original
        const fallbackResult = detectPhishingWithAI(message.data);
        fallbackResult.method = 'hybrid_critical_fallback';
        fallbackResult.error = error.message;
        
        sendResponse(fallbackResult);
      });
    
    return true; // Async response
  }
  
  // Handler pentru verificarea stării Python server
  if (message.action === 'checkPythonServer') {
    checkPythonServerHealth()
      .then(health => sendResponse(health))
      .catch(() => sendResponse(null));
    
    return true;
  }
});

// ============================================
// INIȚIALIZARE (PĂSTRATĂ DIN ORIGINAL)
// ============================================

chrome.runtime.onStartup.addListener(() => {
  console.log('🚀 Phishing Detector Extension started (Ensemble mode)');
  checkPythonServerHealth();
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('📦 Phishing Detector Extension installed (Ensemble mode)');
  console.log('🎯 Algorithm: Original hibrid + Python ensemble (30% RF + 70% hibrid)');
  console.log('🔄 Fallback: Original hibrid algorithm if Python unavailable');
  checkPythonServerHealth();
});

// Test inițial la încărcarea script-ului
console.log('🔧 Background script loaded - Ensemble mode with original algorithm fallback');
console.log('📡 Python server expected at: http://127.0.0.1:5000');
console.log('🎯 Ensemble: 30% RandomForest + 70% Algoritm hibrid original');
console.log('🔄 Fallback: 100% Algoritm hibrid original (dacă Python nu e disponibil)');

// Verificare inițială Python server
checkPythonServerHealth();