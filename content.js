// ─────────────────────────────────────────────
//  CyberGuard — Content Script
//  Tooltip NLP + Llama sur survol des liens
// ─────────────────────────────────────────────

(function () {
  'use strict';

  let tooltipEl = null;

  function createTooltip() {
    const el = document.createElement('div');
    el.id = '__cyberguard_tooltip__';
    el.style.cssText = `
      position:fixed;z-index:2147483647;
      background:#0d1117;color:#e6edf3;
      border:1px solid #30363d;border-radius:10px;
      padding:10px 14px;font-family:'SF Mono','Fira Code',monospace;
      font-size:12px;max-width:340px;pointer-events:none;
      opacity:0;transition:opacity .15s ease;
      box-shadow:0 8px 28px rgba(0,0,0,.5);line-height:1.6;
    `;
    document.body.appendChild(el);
    return el;
  }

  function showTooltip(x, y, html) {
    if (!tooltipEl) tooltipEl = createTooltip();
    tooltipEl.innerHTML = html;
    tooltipEl.style.opacity = '1';
    const left = (x + 14 + 340 > window.innerWidth) ? x - 354 : x + 14;
    const top  = (y + 14 + 130 > window.innerHeight) ? y - 140 : y + 14;
    tooltipEl.style.left = left + 'px';
    tooltipEl.style.top  = top  + 'px';
  }

  function hideTooltip() {
    if (tooltipEl) tooltipEl.style.opacity = '0';
  }

  function scoreColor(s) {
    if (s >= 75) return '#1D9E75';
    if (s >= 45) return '#EF9F27';
    return '#e74c3c';
  }

  function buildTooltipHTML(r) {
    const llama = r.layers?.llama;
    const nlp   = r.layers?.nlp;

    let llamaSection = '';
    if (llama?.available && llama.explanation) {
      llamaSection = `
        <div style="margin-top:6px;padding-top:6px;border-top:1px solid #21262d">
          <span style="color:#4fc3f7;font-size:10px;font-weight:700">🧠 LLAMA 3.2</span><br>
          <span style="color:#cdd9e5;font-size:11px">${llama.explanation}</span>
        </div>`;
    }

    let nlpSection = '';
    if (nlp && (nlp.patterns?.urgency > 0 || nlp.patterns?.fear > 0 || nlp.patterns?.impersonation > 0)) {
      const flags = [];
      if (nlp.patterns.urgency > 0)       flags.push('⚡ Urgence');
      if (nlp.patterns.fear > 0)           flags.push('😨 Peur');
      if (nlp.patterns.impersonation > 0)  flags.push('🎭 Usurpation');
      nlpSection = `<div style="margin-top:4px;font-size:10px;color:#EF9F27">${flags.join(' · ')}</div>`;
    }

    const issues = r.issues || [];

    return `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="color:${scoreColor(r.score)};font-size:16px;font-weight:700">${r.score}</span>
        <span style="color:#8b949e;font-size:10px">/100</span>
        <span style="color:${scoreColor(r.score)};font-size:11px;font-weight:600">
          ${{ safe:'✅ Sûr', warning:'⚠️ Suspect', danger:'🔴 Dangereux' }[r.risk] || ''}
        </span>
        <span style="margin-left:auto;color:#637e98;font-size:10px">${r.details?.hostname || ''}</span>
      </div>
      ${issues.slice(0, 2).map(i =>
        `<div style="color:#f0883e;font-size:11px">⚡ ${i.msg}</div>`
      ).join('')}
      ${r.details?.hasSSL
        ? '<div style="color:#56d364;font-size:11px">🔒 SSL valide</div>'
        : '<div style="color:#f85149;font-size:11px">🔓 Pas de SSL</div>'
      }
      ${nlpSection}
      ${llamaSection}
      ${r.llmPending ? '<div style="color:#4fc3f7;font-size:10px;margin-top:4px">⏳ Analyse Llama en cours…</div>' : ''}
    `;
  }

  // Survol des liens
  document.addEventListener('mouseover', (e) => {
    const link = e.target.closest('a[href]');
    if (!link) return;
    const href = link.href;
    if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;

    chrome.runtime.sendMessage({ action: 'analyzeURL', url: href }, (res) => {
      if (chrome.runtime.lastError || !res?.result) return;
      showTooltip(e.clientX, e.clientY, buildTooltipHTML(res.result));
    });
  });

  document.addEventListener('mousemove', (e) => {
    if (tooltipEl && tooltipEl.style.opacity === '1') {
      const left = (e.clientX + 14 + 340 > window.innerWidth) ? e.clientX - 354 : e.clientX + 14;
      const top  = (e.clientY + 14 + 130 > window.innerHeight) ? e.clientY - 140 : e.clientY + 14;
      tooltipEl.style.left = left + 'px';
      tooltipEl.style.top  = top  + 'px';
    }
  });

  document.addEventListener('mouseout', (e) => {
    if (e.target.closest('a[href]')) hideTooltip();
  });

  // Scanner les liens de la page
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'scanPageLinks') {
      const links = [...document.querySelectorAll('a[href]')]
        .map(a => a.href)
        .filter(h => h.startsWith('http'))
        .filter((v, i, arr) => arr.indexOf(v) === i)
        .slice(0, 50);
      sendResponse({ links, count: links.length });
    }
  });

})();
