// ─────────────────────────────────────────────
//  CyberGuard — Moteur d'analyse unifié
//  Pipeline : Règles → NLP → Llama 3.2
// ─────────────────────────────────────────────

'use strict';

const PHISHING_KEYWORDS = [
  'secure','login','verify','account','update','confirm','banking',
  'paypal','amazon','apple','google','microsoft','netflix','instagram',
  'facebook','support','alert','suspended','unusual','activity',
  'password','credential','signin','sign-in','wallet','crypto'
];

const SUSPICIOUS_TLDS = [
  '.xyz','.tk','.ml','.ga','.cf','.gq','.top','.click',
  '.download','.loan','.work','.party','.review','.science',
  '.date','.racing','.win','.bid','.stream','.faith'
];

const URL_SHORTENERS = [
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.to',
  'buff.ly','adf.ly','cutt.ly','rb.gy','is.gd','v.gd'
];

const KNOWN_SAFE_DOMAINS = [
  'google.com','youtube.com','facebook.com','twitter.com','instagram.com',
  'linkedin.com','amazon.com','apple.com','microsoft.com','github.com',
  'wikipedia.org','reddit.com','netflix.com','paypal.com','ebay.com',
  'stackoverflow.com','mozilla.org','cloudflare.com'
];

const HOMOGRAPH_PATTERN = /[аеіорсухАВСЕЅІЈОРЅТ]/u;

// ── COUCHE 1 : Règles (synchrone) ────────────
function analyzeRules(urlString) {
  const result = {
    url: urlString, score: 100, risk: 'safe',
    issues: [], details: {}, timestamp: Date.now()
  };

  let parsed;
  try { parsed = new URL(urlString); }
  catch {
    result.score = 0; result.risk = 'danger';
    result.issues.push({ type: 'invalid', msg: 'URL invalide ou malformée', severity: 'high' });
    return result;
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullURL  = urlString.toLowerCase();

  result.details = { hostname, protocol: parsed.protocol, hasSSL: parsed.protocol === 'https:', isShortener: false, isTrusted: false };

  if (!result.details.hasSSL) {
    result.score -= 25;
    result.issues.push({ type: 'no-ssl', msg: 'Pas de certificat SSL (HTTP)', severity: 'high' });
  }

  const isTrusted = KNOWN_SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  if (isTrusted) { result.details.isTrusted = true; result.score = Math.min(result.score + 10, 100); }

  if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
    result.details.isShortener = true; result.score -= 20;
    result.issues.push({ type: 'shortener', msg: 'URL raccourcie — destination inconnue', severity: 'medium' });
  }

  const suspTLD = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  if (suspTLD && !isTrusted) {
    result.score -= 20;
    result.issues.push({ type: 'suspicious-tld', msg: `Extension suspecte : ${suspTLD}`, severity: 'medium' });
  }

  const found = PHISHING_KEYWORDS.filter(k => fullURL.includes(k));
  if (found.length && !isTrusted) {
    result.score -= Math.min(found.length * 8, 30);
    result.issues.push({ type: 'keywords', msg: `Mots suspects : ${found.slice(0,3).join(', ')}`, severity: found.length >= 2 ? 'high' : 'medium', keywords: found });
  }

  if (hostname.split('.').length - 2 >= 3 && !isTrusted) {
    result.score -= 15;
    result.issues.push({ type: 'subdomain', msg: 'Trop de sous-domaines', severity: 'medium' });
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    result.score -= 30;
    result.issues.push({ type: 'ip-url', msg: "Adresse IP directe dans l'URL", severity: 'high' });
  }

  if (HOMOGRAPH_PATTERN.test(hostname)) {
    result.score -= 40;
    result.issues.push({ type: 'homograph', msg: 'Caractères Unicode suspects (attaque homographe)', severity: 'critical' });
  }

  if (urlString.length > 200) {
    result.score -= 10;
    result.issues.push({ type: 'long-url', msg: 'URL anormalement longue', severity: 'low' });
  }

  if (fullURL.includes('%25') || fullURL.includes('%2f%2f')) {
    result.score -= 15;
    result.issues.push({ type: 'encoding', msg: 'Encodage URL suspect', severity: 'medium' });
  }

  result.score = Math.max(0, Math.min(100, result.score));
  result.risk  = result.score >= 75 ? 'safe' : result.score >= 45 ? 'warning' : 'danger';
  return result;
}

// ── PIPELINE COMPLET (async) ──────────────────
async function analyzeFullPipeline(input) {
  const rulesResult = analyzeRules(input);
  const nlpResult   = analyzeNLP(input);

  let llamaResult = null;
  let ollamaAvailable = false;

  try {
    ollamaAvailable = await checkOllamaAvailable();
    if (ollamaAvailable) llamaResult = await analyzWithLlama(input, nlpResult);
  } catch (e) {
    console.warn('CyberGuard: Llama graceful fail:', e.message);
  }

  const fused = fuseScores(rulesResult, nlpResult, llamaResult);

  return {
    url: input,
    timestamp: Date.now(),
    score: fused.finalScore,
    risk:  fused.finalRisk,
    layers: {
      rules: { score: rulesResult.score, risk: rulesResult.risk, issues: rulesResult.issues },
      nlp: {
        riskScore: nlpResult.nlpRiskScore,
        patterns:  nlpResult.patterns,
        entropy:   nlpResult.entropy,
        digitRatio: nlpResult.digitRatio,
        tokens:    nlpResult.tokens,
        phishingTFIDF: nlpResult.phishingTFIDF,
        safeTFIDF: nlpResult.safeTFIDF,
      },
      llama: llamaResult
        ? { available: true, ...llamaResult }
        : { available: false, reason: ollamaAvailable ? 'Analyse échouée' : 'Ollama non démarré' }
    },
    breakdown: fused.breakdown,
    details: rulesResult.details,
    issues:  rulesResult.issues,
  };
}

function analyzeQuick(urlString) { return analyzeRules(urlString); }
function getRiskLabel(risk) { return { safe: 'Sûr', warning: 'Suspect', danger: 'Dangereux' }[risk] || 'Inconnu'; }
function getSeverityLabel(s) { return { low: 'Faible', medium: 'Moyen', high: 'Élevé', critical: 'Critique' }[s] || s; }

if (typeof module !== 'undefined') {
  module.exports = { analyzeFullPipeline, analyzeQuick, analyzeRules, getRiskLabel, getSeverityLabel };
}
