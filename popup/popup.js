// ─────────────────────────────────────────────
//  CyberGuard — Popup JS v2 (Règles + NLP + Llama)
// ─────────────────────────────────────────────

// ── Helpers ───────────────────────────────────
function scoreColor(s) {
  if (s >= 75) return '#1D9E75';
  if (s >= 45) return '#EF9F27';
  return '#e74c3c';
}

function riskLabel(r) {
  return { safe: '✅ Sûr', warning: '⚠️ Suspect', danger: '🔴 Dangereux' }[r] || '❓';
}

function sevClass(s) {
  return { low:'sev-low', medium:'sev-medium', high:'sev-high', critical:'sev-critical' }[s] || 'sev-medium';
}

function shortURL(url) {
  try { const u = new URL(url); return u.hostname + (u.pathname !== '/' ? u.pathname.slice(0,18) : ''); }
  catch { return url.slice(0, 40); }
}

// ── Score Ring ────────────────────────────────
function buildScoreRingHTML(score, url, risk, hasSSL, llmPending) {
  const c = scoreColor(score);
  const offset = 188.5 - (score / 100) * 188.5;
  return `
    <div class="score-section">
      <div class="score-ring-wrap">
        <svg width="70" height="70" viewBox="0 0 70 70">
          <circle class="score-ring-bg" cx="35" cy="35" r="29"/>
          <circle class="score-ring-fill" cx="35" cy="35" r="29"
            stroke-dasharray="182.2" stroke-dashoffset="${182.2 - (score/100)*182.2}"
            stroke="${c}"/>
        </svg>
        <div class="score-center">
          <span class="score-number" style="color:${c}">${score}</span>
          <span class="score-label">score</span>
        </div>
      </div>
      <div class="score-info">
        <div class="score-url">${shortURL(url)}</div>
        <div class="risk-badge ${risk}">${riskLabel(risk)}</div>
        <div style="font-size:11px;color:${hasSSL ? '#1D9E75' : '#e74c3c'}">
          ${hasSSL ? '🔒 SSL valide' : '🔓 Pas de SSL'}
        </div>
        ${llmPending ? '<div style="font-size:10px;color:#a78bfa;margin-top:3px">⏳ Llama analyse…</div>' : ''}
      </div>
    </div>`;
}

// ── Breakdown des 3 couches ───────────────────
function buildBreakdownHTML(breakdown) {
  if (!breakdown) return '';
  return `
    <div class="breakdown">
      <div class="breakdown-card">
        <div class="breakdown-label">📏 Règles</div>
        <div class="breakdown-val" style="color:${scoreColor(100 - breakdown.rules)}">${breakdown.rules}%</div>
      </div>
      <div class="breakdown-card">
        <div class="breakdown-label">🔤 NLP</div>
        <div class="breakdown-val" style="color:${scoreColor(100 - breakdown.nlp)}">${breakdown.nlp}%</div>
      </div>
      <div class="breakdown-card">
        <div class="breakdown-label">🧠 Llama</div>
        <div class="breakdown-val" style="color:${scoreColor(100 - breakdown.llama)}">${breakdown.llama}%</div>
      </div>
    </div>`;
}

// ── Panel Llama ───────────────────────────────
function buildLlamaHTML(llama) {
  if (!llama) return '';
  if (!llama.available) {
    return `
      <div class="llama-panel">
        <div class="llama-header"><span class="llama-badge">🧠 LLAMA 3.2</span></div>
        <div class="llama-unavailable">
          ${llama.reason === 'Ollama non démarré'
            ? '⚠️ Ollama non démarré.<br><code style="color:#a78bfa;font-size:10px">ollama serve</code>'
            : '⚠️ ' + (llama.reason || 'Indisponible')}
        </div>
      </div>`;
  }
  const indicators = (llama.indicators || []).slice(0, 4);
  return `
    <div class="llama-panel">
      <div class="llama-header">
        <span class="llama-badge">🧠 LLAMA 3.2</span>
        <span style="font-size:10px;color:#a78bfa">${llama.threat_type || ''}</span>
        <span class="llama-confidence">${llama.confidence || 0}% confiance</span>
      </div>
      <div class="llama-explanation">${llama.explanation || '—'}</div>
      ${indicators.length ? `<div class="llama-indicators">${indicators.map(i => `<span class="llama-indicator">⚡ ${i}</span>`).join('')}</div>` : ''}
      ${llama.recommendation ? `<div class="llama-recommendation">💡 ${llama.recommendation}</div>` : ''}
    </div>`;
}

// ── Panel NLP ─────────────────────────────────
function buildNLPHTML(nlp) {
  if (!nlp) return '';
  const p = nlp.patterns || {};
  const tags = [];
  if (p.urgency > 0)       tags.push(`<span class="pattern-tag urgency">⚡ Urgence ×${p.urgency}</span>`);
  if (p.fear > 0)           tags.push(`<span class="pattern-tag fear">😨 Peur ×${p.fear}</span>`);
  if (p.reward > 0)         tags.push(`<span class="pattern-tag reward">🎁 Récompense ×${p.reward}</span>`);
  if (p.impersonation > 0)  tags.push(`<span class="pattern-tag impersonation">🎭 Usurpation ×${p.impersonation}</span>`);

  return `
    <div class="nlp-panel">
      <div class="nlp-header">
        <span class="nlp-badge">🔤 NLP</span>
        <span style="font-size:10px;color:var(--muted);margin-left:auto">Risque: <b style="color:${scoreColor(100-nlp.riskScore)}">${nlp.riskScore}/100</b></span>
      </div>
      <div class="nlp-grid">
        <div class="nlp-stat">
          <div class="nlp-stat-label">Entropie</div>
          <div class="nlp-stat-val" style="color:${nlp.entropy > 3.8 ? '#e74c3c' : '#1D9E75'}">${nlp.entropy}</div>
        </div>
        <div class="nlp-stat">
          <div class="nlp-stat-label">Ratio chiffres</div>
          <div class="nlp-stat-val" style="color:${nlp.digitRatio > 0.3 ? '#e74c3c' : '#1D9E75'}">${(nlp.digitRatio * 100).toFixed(0)}%</div>
        </div>
        <div class="nlp-stat">
          <div class="nlp-stat-label">TF-IDF Phishing</div>
          <div class="nlp-stat-val" style="color:${nlp.phishingTFIDF > nlp.safeTFIDF ? '#e74c3c' : '#1D9E75'}">${nlp.phishingTFIDF}</div>
        </div>
        <div class="nlp-stat">
          <div class="nlp-stat-label">TF-IDF Safe</div>
          <div class="nlp-stat-val" style="color:var(--safe)">${nlp.safeTFIDF}</div>
        </div>
      </div>
      ${tags.length ? `<div class="pattern-row">${tags.join('')}</div>` : '<div style="font-size:11px;color:var(--muted)">✅ Aucun pattern suspect</div>'}
    </div>`;
}

// ── Issues ────────────────────────────────────
function buildIssuesHTML(issues) {
  if (!issues || issues.length === 0)
    return '<div class="no-issues">✅ Aucun problème détecté</div>';
  return `<div class="issues-list">${
    issues.map(i => `
      <div class="issue-item">
        <div class="issue-dot ${sevClass(i.severity)}"></div>
        <div class="issue-msg">${i.msg}</div>
        <div style="font-size:10px;color:var(--muted)">${i.severity || ''}</div>
      </div>`).join('')
  }</div>`;
}

// ── Render full result ────────────────────────
function renderFullResult(result, container) {
  if (!result) { container.innerHTML = `<div style="color:var(--muted);text-align:center;padding:20px;font-size:12px">Aucun résultat.</div>`; return; }

  const llmPending = result.llmPending || false;
  const layers = result.layers || {};

  container.innerHTML =
    buildScoreRingHTML(result.score, result.url || '', result.risk, result.details?.hasSSL, llmPending) +
    buildBreakdownHTML(result.breakdown) +
    buildLlamaHTML(layers.llama) +
    buildNLPHTML(layers.nlp) +
    `<div class="section-title">Problèmes détectés (${(result.issues||[]).length})</div>` +
    buildIssuesHTML(result.issues);
}

// ── Ollama Status ─────────────────────────────
function checkOllamaStatus() {
  const dot = document.getElementById('ollama-dot');
  const status = document.getElementById('ollama-status');
  chrome.runtime.sendMessage({ action: 'checkOllama' }, (res) => {
    if (!res) return;
    if (res.available && res.modelReady) {
      dot.className = 'ollama-dot on';
      status.textContent = 'Ollama actif · llama3.2 prêt';
      status.style.color = '#1D9E75';
    } else if (res.available && !res.modelReady) {
      dot.className = 'ollama-dot checking';
      status.textContent = 'Ollama actif · llama3.2 non installé → ollama pull llama3.2';
      status.style.color = '#EF9F27';
    } else {
      dot.className = 'ollama-dot off';
      status.textContent = 'Ollama non démarré → ollama serve';
      status.style.color = '#e74c3c';
    }
  });
}

// ── Tab: Analyse ──────────────────────────────
function loadCurrentAnalysis() {
  const loadingEl = document.getElementById('loading-main');
  const llamaEl   = document.getElementById('loading-llama');
  const contentEl = document.getElementById('analyze-content');
  const emptyEl   = document.getElementById('analyze-empty');

  loadingEl.classList.add('visible');
  llamaEl.classList.remove('visible');
  contentEl.style.display = 'none';
  emptyEl.style.display = 'none';

  chrome.runtime.sendMessage({ action: 'getCurrentAnalysis' }, (res) => {
    loadingEl.classList.remove('visible');
    if (!res?.result) { emptyEl.style.display = 'block'; return; }

    contentEl.style.display = 'block';
    const r = res.result;

    if (r.llmPending) llamaEl.classList.add('visible');
    renderFullResult(r, contentEl);
  });
}

// Écouter les mises à jour Llama
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === 'analysisUpdated') {
    const active = document.querySelector('.tab.active')?.dataset?.tab;
    if (active === 'analyze') {
      document.getElementById('loading-llama')?.classList.remove('visible');
      const contentEl = document.getElementById('analyze-content');
      if (contentEl) renderFullResult(msg.result, contentEl);
    }
  }
  if (msg.action === 'manualAnalysisComplete') {
    document.getElementById('loading-manual-llama')?.classList.remove('visible');
    const resultEl = document.getElementById('manual-result');
    if (resultEl && msg.result) renderFullResult(msg.result, resultEl);
  }
});

// ── Tab: Manuel ───────────────────────────────
function setupManualTab() {
  const input    = document.getElementById('manual-input');
  const btn      = document.getElementById('manual-btn');
  const resultEl = document.getElementById('manual-result');
  const loadEl   = document.getElementById('loading-manual');
  const llamaEl  = document.getElementById('loading-manual-llama');

  function doAnalyze() {
    let url = input.value.trim();
    if (!url) return;
    if (!url.startsWith('http')) url = 'https://' + url;
    loadEl.classList.add('visible');
    llamaEl.classList.remove('visible');
    resultEl.innerHTML = '';

    chrome.runtime.sendMessage({ action: 'analyzeURL', url }, (res) => {
      loadEl.classList.remove('visible');
      if (res?.result) {
        renderFullResult(res.result, resultEl);
        // Attendre Llama
        llamaEl.classList.add('visible');
      }
    });
  }

  btn.addEventListener('click', doAnalyze);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') doAnalyze(); });
}

// ── Tab: Scanner ──────────────────────────────
function setupScanTab() {
  document.getElementById('scan-btn').addEventListener('click', () => {
    const resultEl   = document.getElementById('scan-result');
    const loadingEl  = document.getElementById('loading-scan');
    const progressEl = document.getElementById('scan-progress');
    resultEl.innerHTML = '';
    loadingEl.classList.add('visible');
    progressEl.textContent = 'Récupération des liens…';

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) { loadingEl.classList.remove('visible'); return; }
      chrome.tabs.sendMessage(tabs[0].id, { action: 'scanPageLinks' }, (res) => {
        if (chrome.runtime.lastError || !res?.links) {
          loadingEl.classList.remove('visible');
          resultEl.innerHTML = `<div style="color:var(--muted);font-size:12px;padding:8px">Impossible de scanner cette page.</div>`;
          return;
        }
        const links = res.links.slice(0, 20);
        if (!links.length) {
          loadingEl.classList.remove('visible');
          resultEl.innerHTML = `<div style="color:var(--muted);font-size:12px;padding:8px">Aucun lien trouvé.</div>`;
          return;
        }
        let done = 0;
        const results = [];
        links.forEach(url => {
          chrome.runtime.sendMessage({ action: 'analyzeURL', url }, (res) => {
            done++;
            progressEl.textContent = `Analyse ${done}/${links.length}…`;
            if (res?.result) results.push(res.result);
            if (done === links.length) {
              loadingEl.classList.remove('visible');
              results.sort((a, b) => a.score - b.score);
              const s = { safe: results.filter(r=>r.risk==='safe').length, warning: results.filter(r=>r.risk==='warning').length, danger: results.filter(r=>r.risk==='danger').length };
              resultEl.innerHTML = `
                <div style="display:flex;gap:6px;margin-bottom:8px">
                  <div class="detail-card" style="flex:1;text-align:center"><div class="detail-label">Total</div><div class="detail-value neutral">${results.length}</div></div>
                  <div class="detail-card" style="flex:1;text-align:center"><div class="detail-label">Sûrs</div><div class="detail-value ok">${s.safe}</div></div>
                  <div class="detail-card" style="flex:1;text-align:center"><div class="detail-label">Suspects</div><div class="detail-value" style="color:#EF9F27">${s.warning}</div></div>
                  <div class="detail-card" style="flex:1;text-align:center"><div class="detail-label">Danger</div><div class="detail-value bad">${s.danger}</div></div>
                </div>
                ${results.map(r => `<div class="scan-result-item ${r.risk}"><span style="font-weight:700;min-width:26px">${r.score}</span><span style="flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${shortURL(r.url)}</span></div>`).join('')}
              `;
            }
          });
        });
      });
    });
  });
}

// ── Tab: History ──────────────────────────────
function loadHistory() {
  const listEl = document.getElementById('history-list');
  chrome.runtime.sendMessage({ action: 'getHistory' }, (res) => {
    const history = res?.history || [];
    if (!history.length) { listEl.innerHTML = `<div class="history-empty">Aucune analyse pour l'instant.</div>`; return; }
    listEl.innerHTML = history.slice(0, 30).map(r => `
      <div class="history-item">
        <span class="hist-score" style="color:${scoreColor(r.score)}">${r.score}</span>
        <span class="hist-url">${shortURL(r.url)}</span>
        ${r.layers?.llama?.available ? `<span class="hist-llama">🧠</span>` : ''}
        <span class="hist-badge ${r.risk}">${{safe:'Sûr',warning:'Suspect',danger:'Danger'}[r.risk]}</span>
      </div>`).join('');
  });
}

function setupHistoryTab() {
  document.getElementById('clear-history-btn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'clearHistory' }, () => {
      document.getElementById('history-list').innerHTML = `<div class="history-empty">Aucune analyse pour l'instant.</div>`;
    });
  });
}

// ── Tabs ──────────────────────────────────────
function setupTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
      if (tab.dataset.tab === 'analyze') loadCurrentAnalysis();
      if (tab.dataset.tab === 'history') loadHistory();
    });
  });
}

// ── Init ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupManualTab();
  setupScanTab();
  setupHistoryTab();
  checkOllamaStatus();
  loadCurrentAnalysis();
  // Vérifier Ollama toutes les 30s
  setInterval(checkOllamaStatus, 30000);
});
