// ─────────────────────────────────────────────
//  CyberGuard — Service Worker
//  Pipeline : Règles → NLP → Llama 3.2
// ─────────────────────────────────────────────

importScripts('utils/nlp.js', 'utils/llama.js', 'utils/analyzer.js');

const CACHE_MS = 24 * 60 * 60 * 1000;
const analysisCache = new Map();

function getCached(url) {
  const e = analysisCache.get(url);
  if (!e || Date.now() - e.timestamp > CACHE_MS) { analysisCache.delete(url); return null; }
  return e.result;
}

function setCache(url, result) {
  analysisCache.set(url, { result, timestamp: Date.now() });
  if (analysisCache.size > 500) analysisCache.delete(analysisCache.keys().next().value);
}

function updateBadge(tabId, result) {
  const colors = { safe: '#1D9E75', warning: '#BA7517', danger: '#A32D2D' };
  const labels  = { safe: '',       warning: '!',       danger: '✕' };
  chrome.action.setBadgeBackgroundColor({ color: colors[result.risk] || '#888', tabId });
  chrome.action.setBadgeText({ text: labels[result.risk] ?? '', tabId });
  chrome.action.setTitle({ title: `CyberGuard — Score: ${result.score}/100 (${getRiskLabel(result.risk)})`, tabId });
}

async function analyzeTab(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  const cached = getCached(url);
  if (cached) {
    updateBadge(tabId, cached);
    await chrome.storage.session.set({ [`tab_${tabId}`]: cached });
    return;
  }

  // Résultat rapide immédiat
  const quick = analyzeQuick(url);
  updateBadge(tabId, quick);
  await chrome.storage.session.set({ [`tab_${tabId}`]: { ...quick, llmPending: true } });

  // Pipeline complet en async
  try {
    const full = await analyzeFullPipeline(url);
    setCache(url, full);
    await chrome.storage.session.set({ [`tab_${tabId}`]: full });
    updateBadge(tabId, full);
    saveToHistory(full);
    chrome.runtime.sendMessage({ action: 'analysisUpdated', tabId, result: full }).catch(() => {});
  } catch (e) {
    setCache(url, quick);
    await chrome.storage.session.set({ [`tab_${tabId}`]: quick });
    saveToHistory(quick);
  }
}

async function saveToHistory(result) {
  try {
    const data = await chrome.storage.local.get('history');
    const history = data.history || [];
    if (history.length > 0 && history[0].url === result.url) return;
    history.unshift(result);
    if (history.length > 50) history.pop();
    await chrome.storage.local.set({ history });
  } catch (e) { console.error('History:', e); }
}

chrome.webNavigation.onCompleted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  await analyzeTab(d.tabId, d.url);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab.url) await analyzeTab(tabId, tab.url);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.action === 'analyzeURL') {
    const quick = analyzeQuick(msg.url);
    sendResponse({ result: quick, partial: true });
    analyzeFullPipeline(msg.url).then(full => {
      setCache(msg.url, full);
      saveToHistory(full);
      chrome.runtime.sendMessage({ action: 'manualAnalysisComplete', url: msg.url, result: full }).catch(() => {});
    });
    return true;
  }

  if (msg.action === 'getCurrentAnalysis') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs[0]) { sendResponse({ result: null }); return; }
      const data = await chrome.storage.session.get(`tab_${tabs[0].id}`);
      sendResponse({ result: data[`tab_${tabs[0].id}`] || null, url: tabs[0].url });
    });
    return true;
  }

  if (msg.action === 'checkOllama') {
    checkOllamaAvailable().then(ok => {
      if (ok) checkModelAvailable().then(model => sendResponse({ available: ok, modelReady: model }));
      else sendResponse({ available: false, modelReady: false });
    });
    return true;
  }

  if (msg.action === 'getHistory') {
    chrome.storage.local.get('history', d => sendResponse({ history: d.history || [] }));
    return true;
  }

  if (msg.action === 'clearHistory') {
    chrome.storage.local.set({ history: [] }, () => sendResponse({ ok: true }));
    return true;
  }
});
