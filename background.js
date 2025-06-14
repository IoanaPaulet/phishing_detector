
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
  /(credit.?card|card.?number)/i,
  /(social.?security|SSN)/i,
  /(account.?number|routing.?number)/i,
  /(PIN|personal.?identification.?number)/i,
  /(username|user.?id).{1,20}(and|&).{1,20}password/i,
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
  "billing@microsoft.com",
  
];
function detectPhishingWithAI(emailData) {
  const subject = emailData.subject || '';
  const body = emailData.body || '';
  const links = emailData.links || [];
  const sender = emailData.sender || '';
  
  if (trustedSenders.some(trusted => sender.toLowerCase().includes(trusted))) {
    console.log('Expeditor de încredere detectat:', sender);
    return {
      isPhishing: false,
      score: 0,
      reasons: ["Expeditor de încredere"]
    };
  }
  
  const text = subject + ' ' + body;
  const textLower = text.toLowerCase();
  

  let score = 0.0;
  const reasons = [];
  const debugInfo = {}; 
  
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

  score = Math.max(0, Math.min(1, score));
  

  const isPhishing = score > 0.7;
  
  if (reasons.length > 5) {
    reasons.splice(5);
  } else if (reasons.length === 0) {
    reasons.push("Nu am identificat motive specifice de îngrijorare.");
  }
  console.log('Analiză phishing:', {
    score: score,
    isPhishing: isPhishing,
    subject: subject,
    debug: debugInfo
  });
  
  return {
    isPhishing: isPhishing,
    score: score,
    reasons: reasons
  };
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'analyzeEmail') {
    const result = detectPhishingWithAI(message.data);
    chrome.storage.local.set({ 
      lastAnalysis: {
        timestamp: Date.now(),
        data: message.data,
        result: result
      }
    });
    
    if (result.isPhishing) {
      chrome.tabs.sendMessage(sender.tab.id, {
        action: 'showWarning',
        isPhishing: result.isPhishing,
        score: result.score,
        reasons: result.reasons
      });
    }
    
    sendResponse(result);
  }
  
  return true; 
});