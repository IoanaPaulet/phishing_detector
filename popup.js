/**
 * Phishing Detector Extension - Popup Script
 * Gestionează interfața popup și comunicarea cu background script
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elemente UI
  const statusContainer = document.getElementById('status-container');
  const statusText = document.querySelector('.status-text');
  const statusIcon = document.querySelector('.status-icon');
  const details = document.getElementById('details');
  const reasonsList = document.getElementById('reasons-list');
  const scanBtn = document.getElementById('scan-btn');
  const settingsLink = document.getElementById('settings-link');
  const historyLink = document.getElementById('history-link');
  
  // Încărcăm ultima analiză din storage
  loadLastAnalysis();
  
  /**
   * Încarcă ultima analiză din storage Chrome
   */
  function loadLastAnalysis() {
    chrome.storage.local.get('lastAnalysis', (data) => {
      if (data.lastAnalysis) {
        // Verificăm dacă analiza nu este mai veche de 1 oră
        const isRecent = (Date.now() - data.lastAnalysis.timestamp) < 3600000;
        
        if (isRecent) {
          updateUI(data.lastAnalysis.result);
        } else {
          setDefaultStatus();
        }
      } else {
        setDefaultStatus();
      }
    });
  }
  
  /**
   * Afișează un status implicit când nu există analiză recentă
   */
  function setDefaultStatus() {
    statusContainer.className = 'status safe';
    statusIcon.textContent = 'ℹ️';
    statusText.textContent = 'Niciun email scanat recent. Apasă butonul pentru a scana emailul curent.';
    details.style.display = 'none';
  }
  
  /**
   * Actualizează UI cu rezultatele analizei
   */
  function updateUI(result) {
    if (result.error) {
      statusContainer.className = 'status warning';
      statusIcon.textContent = '⚠️';
      statusText.textContent = 'Eroare la scanare: ' + result.error;
      details.style.display = 'none';
      return;
    }
    
    // Actualizăm statusul în funcție de scor
    if (result.isPhishing) {
      if (result.score > 0.8) {
        statusContainer.className = 'status danger';
        statusIcon.textContent = '🚨';
        statusText.textContent = `Risc ridicat de phishing (${Math.round(result.score * 100)}%)`;
      } else {
        statusContainer.className = 'status warning';
        statusIcon.textContent = '⚠️';
        statusText.textContent = `Posibil phishing (${Math.round(result.score * 100)}%)`;
      }
    } else {
      statusContainer.className = 'status safe';
      statusIcon.textContent = '✓';
      statusText.textContent = 'Emailul pare sigur';
    }
    
    // Actualizăm lista de motive
    reasonsList.innerHTML = '';
    if (result.reasons && result.reasons.length > 0) {
      result.reasons.forEach(reason => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
      });
      
      details.style.display = 'block';
    } else {
      details.style.display = 'none';
    }
  }
  
  /**
   * Scanează emailul curent în tabul activ
   */
  function scanCurrentEmail() {
    statusContainer.className = 'status';
    statusIcon.textContent = '⏳';
    statusText.textContent = 'Scanare în curs...';
    
    // Obținem tab-ul activ
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      
      // Verificăm dacă suntem pe Gmail
      if (activeTab.url.includes('mail.google.com')) {
        // Cerem conținutul emailului de la content script
        chrome.tabs.sendMessage(activeTab.id, { action: 'getEmailContent' }, (emailData) => {
          if (chrome.runtime.lastError) {
            updateUI({ 
              error: 'Content script nu este disponibil. Reîncarcă pagina.' 
            });
            return;
          }
          
          if (!emailData) {
            updateUI({ 
              error: 'Niciun email deschis. Deschide un email pentru a-l scana.' 
            });
            return;
          }
          
          // Trimitem datele către background script pentru analiză
          chrome.runtime.sendMessage({ 
            action: 'analyzeEmail', 
            data: emailData 
          }, (result) => {
            if (chrome.runtime.lastError) {
              updateUI({ 
                error: 'Eroare la comunicarea cu background script.' 
              });
              return;
            }
            
            // Actualizăm UI-ul cu rezultatele
            updateUI(result);
          });
        });
      } else {
        updateUI({ 
          error: 'Extensia funcționează doar pe Gmail. Deschide Gmail pentru a o utiliza.' 
        });
      }
    });
  }
  
  // Event listener pentru butonul de scanare
  scanBtn.addEventListener('click', scanCurrentEmail);
  
  // Event listener pentru link-ul de setări
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'settings.html' });
  });
  
  // Event listener pentru link-ul de istoric
  historyLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'history.html' });
  });
});