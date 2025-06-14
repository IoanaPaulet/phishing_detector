(async () => {
    if (typeof tf === "undefined") {
      const s = document.createElement("script");
      s.src = "https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.11.0/dist/tf.min.js";
      document.head.appendChild(s);
      await new Promise(r => s.onload = r);
    }
  
    await tf.ready();
    const model = await tf.loadLayersModel(
      chrome.runtime.getURL("model/model.json")
    );
  
 
    chrome.runtime.sendMessage({ action: "scanEmail" }, async (resp) => {
      const words = resp.text.toLowerCase().split(/\W+/).slice(0, 100);
      const vocab = { /* mapare cuvânt→indice, inclus în detector.js */ };
      const indices = words.map(w => vocab[w] || 0);
      while (indices.length < 100) indices.push(0);
      const input = tf.tensor2d([indices], [1, 100]);
      
      const [score] = await model.predict(input).data();
      showBanner(score);
    });
  })();
  
  function showBanner(score) {
    const div = document.createElement("div");
    Object.assign(div.style, {
      position: "fixed", top: "10px", right: "10px",
      padding: "10px", backgroundColor: score>0.5? "red":"green",
      color: "#fff", fontSize: "14px", zIndex: "9999"
    });
    div.textContent = score>0.5
      ? `⚠️ Posibil phishing (scor: ${score.toFixed(2)})`
      : `✅ Probabil sigur (scor: ${score.toFixed(2)})`;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 4000);
  }
  