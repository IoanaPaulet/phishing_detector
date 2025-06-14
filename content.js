/**

 * Interacționează cu pagina Gmail pentru a extrage conținutul emailurilor 
 * și a afișa avertismente pentru utilizator.
 */

function extractEmailContent() {
  const emailContent = document.querySelector('.a3s.aiL');
  
  if (emailContent) {
    const subject = document.querySelector('.hP')?.textContent || '';
  
    const body = emailContent.innerText || '';
  
    const links = Array.from(emailContent.querySelectorAll('a'))
      .map(a => a.href)
      .filter(link => link && !link.startsWith('mailto:'));
    
  
    return { subject, body, links };
  }
  
  return null;
}

function setupObserver() {
  
  const observer = new MutationObserver((mutations) => {
    if (document.querySelector('.a3s.aiL')) {
      const emailData = extractEmailContent();
      if (emailData) {
        chrome.runtime.sendMessage({
          action: 'analyzeEmail',
          data: emailData
        });
      }
    }
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function showPhishingWarning(score, reasons) {
  const existingWarning = document.getElementById('phishing-warning');
  if (existingWarning) {
    existingWarning.remove();
  }
  
  // Creăm elementul de avertizare
  const warningDiv = document.createElement('div');
  warningDiv.id = 'phishing-warning';
  warningDiv.style.cssText = `
    position: fixed;
    top: 10px;
    right: 10px;
    background-color: ${score > 0.8 ? '#ff4d4d' : '#ffcc00'};
    color: ${score > 0.8 ? 'white' : 'black'};
    padding: 15px;
    border-radius: 5px;
    z-index: 10000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    max-width: 300px;
    font-family: Arial, sans-serif;
  `;
  
  // Adăugăm conținut
  warningDiv.innerHTML = `
    <h3 style="margin-top: 0; margin-bottom: 10px;">⚠️ Posibil Phishing Detectat</h3>
    <p style="margin: 5px 0;">Scor de risc: ${Math.round(score * 100)}%</p>
    <p style="margin: 5px 0;"><strong>Motive:</strong></p>
    <ul style="margin: 5px 0; padding-left: 20px;">${reasons.map(reason => `<li>${reason}</li>`).join('')}</ul>
    <button id="close-warning" style="background: #333; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-top: 10px;">Închide</button>
  `;
  

  document.body.appendChild(warningDiv);
  
  
  document.getElementById('close-warning').addEventListener('click', () => {
    warningDiv.remove();
  });
  
  setTimeout(() => {
    if (document.body.contains(warningDiv)) {
      warningDiv.remove();
    }
  }, 30000);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getEmailContent') {
    sendResponse(extractEmailContent());
  } else if (message.action === 'showWarning' && message.isPhishing) {
    showPhishingWarning(message.score, message.reasons);
  }
  return true; 
});

window.addEventListener('load', () => {
  const initialEmail = extractEmailContent();
  if (initialEmail) {
    chrome.runtime.sendMessage({
      action: 'analyzeEmail',
      data: initialEmail
    });
  }
  
  setupObserver();
});

console.log('Phishing Detector Extension - Content script încărcat și activ');