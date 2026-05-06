// ─────────────────────────────────────────────
//  CyberGuard — Module NLP
//  Preprocessing, TF-IDF, N-grams, Feature Extraction
// ─────────────────────────────────────────────

'use strict';

// ── Corpus de référence (phishing vs légitimes) ──
const PHISHING_CORPUS = [
  'verify your account immediately',
  'confirm your password now',
  'suspended account login required',
  'update billing information urgent',
  'click here to avoid suspension',
  'your paypal account limited',
  'amazon security alert verify',
  'unusual signin activity detected',
  'bank account locked verify identity',
  'free gift claim now limited',
  'congratulations you have been selected',
  'your apple id has been disabled',
  'microsoft security warning virus detected',
  'reset password immediately required action',
  'your package could not be delivered',
];

const SAFE_CORPUS = [
  'welcome to our homepage',
  'browse our product catalog',
  'read the latest news articles',
  'contact us for support',
  'view your order history',
  'explore our documentation',
  'download the latest version',
  'sign in to your account',
  'search results for your query',
  'privacy policy terms of service',
];

// ── Tokenisation ─────────────────────────────
function tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s\-_.]/g, ' ')
    .split(/[\s\-_.\/]+/)
    .filter(t => t.length > 1);
}

// Tokenise une URL en extraisant toutes ses parties
function tokenizeURL(urlString) {
  try {
    const url = new URL(urlString);
    const parts = [
      url.hostname,
      url.pathname,
      url.search,
      url.hash
    ].join(' ');
    return tokenize(parts);
  } catch {
    return tokenize(urlString);
  }
}

// ── N-grams ──────────────────────────────────
function ngrams(tokens, n) {
  const result = [];
  for (let i = 0; i <= tokens.length - n; i++) {
    result.push(tokens.slice(i, i + n).join('_'));
  }
  return result;
}

function getBigrams(tokens)  { return ngrams(tokens, 2); }
function getTrigrams(tokens) { return ngrams(tokens, 3); }

// ── TF-IDF ────────────────────────────────────
function termFrequency(tokens) {
  const tf = {};
  tokens.forEach(t => { tf[t] = (tf[t] || 0) + 1; });
  const total = tokens.length || 1;
  Object.keys(tf).forEach(k => { tf[k] /= total; });
  return tf;
}

function buildIDF(corpus) {
  const idf = {};
  const N = corpus.length;
  corpus.forEach(doc => {
    const unique = new Set(tokenize(doc));
    unique.forEach(term => { idf[term] = (idf[term] || 0) + 1; });
  });
  Object.keys(idf).forEach(k => {
    idf[k] = Math.log(N / idf[k]);
  });
  return idf;
}

// IDF pré-calculé sur notre corpus
const PHISHING_IDF = buildIDF(PHISHING_CORPUS);
const SAFE_IDF     = buildIDF(SAFE_CORPUS);

function tfidfScore(tokens, idf) {
  const tf = termFrequency(tokens);
  let score = 0;
  Object.keys(tf).forEach(term => {
    if (idf[term]) score += tf[term] * idf[term];
  });
  return score;
}

// ── Patterns linguistiques suspects ──────────
const URGENCY_PATTERNS = [
  /urgent/i, /immedi/i, /now/i, /immediately/i, /expire/i,
  /limited/i, /action.required/i, /verify.now/i, /act.now/i,
  /\d+.hours?/i, /\d+.minutes?/i, /today.only/i
];

const FEAR_PATTERNS = [
  /suspend/i, /blocked/i, /locked/i, /disabled/i, /unauthori/i,
  /unusual/i, /suspicious/i, /compromised/i, /hacked/i, /violated/i,
  /warning/i, /alert/i, /danger/i, /risk/i
];

const REWARD_PATTERNS = [
  /free/i, /winner/i, /won/i, /prize/i, /gift/i, /reward/i,
  /congratul/i, /selected/i, /lucky/i, /bonus/i, /cash/i, /\$\d+/i
];

const IMPERSONATION_PATTERNS = [
  /paypal/i, /amazon/i, /apple/i, /google/i, /microsoft/i,
  /facebook/i, /instagram/i, /netflix/i, /bank/i, /chase/i,
  /wellsfargo/i, /citibank/i, /irs/i, /fedex/i, /ups/i, /dhl/i
];

function detectPatterns(text) {
  const lower = text.toLowerCase();
  return {
    urgency:        URGENCY_PATTERNS.filter(p => p.test(lower)).length,
    fear:           FEAR_PATTERNS.filter(p => p.test(lower)).length,
    reward:         REWARD_PATTERNS.filter(p => p.test(lower)).length,
    impersonation:  IMPERSONATION_PATTERNS.filter(p => p.test(lower)).length,
  };
}

// ── Entropie de Shannon (URLs obfusquées) ────
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc + p * Math.log2(p);
  }, 0);
}

// ── Ratio chiffres/lettres ────────────────────
function digitRatio(str) {
  const digits = (str.match(/\d/g) || []).length;
  return digits / (str.length || 1);
}

// ── Similarité cosinus entre deux vecteurs TF ─
function cosineSimilarity(vec1, vec2) {
  const keys = new Set([...Object.keys(vec1), ...Object.keys(vec2)]);
  let dot = 0, norm1 = 0, norm2 = 0;
  keys.forEach(k => {
    const a = vec1[k] || 0, b = vec2[k] || 0;
    dot   += a * b;
    norm1 += a * a;
    norm2 += b * b;
  });
  return dot / (Math.sqrt(norm1) * Math.sqrt(norm2) || 1);
}

// ── Analyse NLP principale ────────────────────
function analyzeNLP(input) {
  const tokens    = tokenizeURL(input);
  const bigrams   = getBigrams(tokens);
  const trigrams  = getTrigrams(tokens);
  const allTokens = [...tokens, ...bigrams, ...trigrams];

  const tf = termFrequency(allTokens);

  // Scores TF-IDF vs corpus phishing / safe
  const phishingScore = tfidfScore(allTokens, PHISHING_IDF);
  const safeScore     = tfidfScore(allTokens, SAFE_IDF);

  // Patterns linguistiques
  const patterns = detectPatterns(input);
  const patternScore = (
    patterns.urgency       * 15 +
    patterns.fear          * 15 +
    patterns.reward        * 10 +
    patterns.impersonation * 20
  );

  // Entropie (URL obfusquée = entropie élevée)
  let hostname = input;
  try { hostname = new URL(input).hostname; } catch {}
  const entropy   = shannonEntropy(hostname);
  const digRatio  = digitRatio(hostname);

  // Score NLP final (0 = safe, 100 = phishing)
  let nlpRiskScore = 0;

  // TF-IDF ratio phishing vs safe
  if (phishingScore > safeScore) {
    nlpRiskScore += Math.min((phishingScore / (safeScore + 0.001)) * 20, 35);
  }

  // Patterns
  nlpRiskScore += Math.min(patternScore, 40);

  // Entropie élevée = suspect
  if (entropy > 3.8) nlpRiskScore += 15;
  if (entropy > 4.2) nlpRiskScore += 10;

  // Ratio de chiffres élevé
  if (digRatio > 0.3) nlpRiskScore += 10;

  nlpRiskScore = Math.min(100, Math.round(nlpRiskScore));

  return {
    nlpRiskScore,
    tokens: tokens.slice(0, 10),
    bigrams: bigrams.slice(0, 5),
    patterns,
    entropy: Math.round(entropy * 100) / 100,
    digitRatio: Math.round(digRatio * 100) / 100,
    phishingTFIDF: Math.round(phishingScore * 1000) / 1000,
    safeTFIDF:     Math.round(safeScore * 1000) / 1000,
  };
}

// Export
if (typeof module !== 'undefined') {
  module.exports = { analyzeNLP, tokenize, tokenizeURL, detectPatterns, shannonEntropy };
}
