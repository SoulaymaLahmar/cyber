// ─────────────────────────────────────────────
//  CyberGuard — Client Llama 3.2 via Ollama
//  Endpoint: http://localhost:11434
// ─────────────────────────────────────────────

'use strict';

const OLLAMA_BASE    = 'http://localhost:11434';
const OLLAMA_MODEL   = 'llama3.2';
const TIMEOUT_MS     = 15000;

// ── Prompt système ────────────────────────────
const SYSTEM_PROMPT = `Tu es CyberGuard, un expert en cybersécurité spécialisé dans la détection de menaces web.
Ton rôle est d'analyser des URLs et des messages pour détecter : phishing, malware, scams, spam, ingénierie sociale.

Réponds UNIQUEMENT en JSON valide avec cette structure exacte :
{
  "verdict": "safe" | "warning" | "danger",
  "confidence": 0-100,
  "threat_type": "none" | "phishing" | "malware" | "scam" | "spam" | "suspicious",
  "explanation": "explication courte en français (max 2 phrases)",
  "indicators": ["indicateur1", "indicateur2"],
  "recommendation": "conseil court en français"
}

Règles :
- Sois précis et concis
- Base-toi sur les patterns linguistiques, la structure de l'URL, et le contexte
- Ne donne JAMAIS d'autre texte que le JSON
- Les indicators sont les éléments suspects que tu as détectés`;

// ── Vérifier si Ollama est disponible ─────────
async function checkOllamaAvailable() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(`${OLLAMA_BASE}/api/tags`, {
      signal: controller.signal
    });
    clearTimeout(timeout);
    return res.ok;
  } catch {
    return false;
  }
}

// ── Vérifier si le modèle est disponible ──────
async function checkModelAvailable() {
  try {
    const res = await fetch(`${OLLAMA_BASE}/api/tags`);
    const data = await res.json();
    const models = data.models || [];
    return models.some(m => m.name.startsWith(OLLAMA_MODEL));
  } catch {
    return false;
  }
}

// ── Appel principal à Llama 3.2 ───────────────
async function analyzWithLlama(input, nlpContext = null) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  // Construire le prompt utilisateur enrichi avec le contexte NLP
  let userPrompt = `Analyse cette URL/texte pour détecter des menaces de cybersécurité :\n\n"${input}"`;

  if (nlpContext) {
    userPrompt += `\n\nContexte NLP pré-analysé :
- Score de risque NLP : ${nlpContext.nlpRiskScore}/100
- Tokens extraits : ${nlpContext.tokens.join(', ')}
- Patterns urgence détectés : ${nlpContext.patterns.urgency}
- Patterns peur détectés : ${nlpContext.patterns.fear}
- Patterns récompense détectés : ${nlpContext.patterns.reward}
- Patterns usurpation d'identité : ${nlpContext.patterns.impersonation}
- Entropie Shannon : ${nlpContext.entropy}
- Ratio chiffres : ${nlpContext.digitRatio}
- Score TF-IDF phishing : ${nlpContext.phishingTFIDF}
- Score TF-IDF safe : ${nlpContext.safeTFIDF}

Utilise ces données comme contexte supplémentaire pour affiner ton analyse.`;
  }

  try {
    const response = await fetch(`${OLLAMA_BASE}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model:  OLLAMA_MODEL,
        system: SYSTEM_PROMPT,
        prompt: userPrompt,
        stream: false,
        options: {
          temperature:  0.1,   // Très déterministe pour la sécurité
          top_p:        0.9,
          num_predict:  300,
          stop: ['\n\n', '```']
        }
      })
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`Ollama HTTP ${response.status}`);
    }

    const data = await response.json();
    const raw  = data.response || '';

    // Parser le JSON retourné par Llama
    return parseLlamaResponse(raw, input);

  } catch (err) {
    clearTimeout(timeout);

    if (err.name === 'AbortError') {
      return { error: 'timeout', message: 'Llama 3.2 a mis trop de temps à répondre (>15s)' };
    }
    if (err.message.includes('fetch')) {
      return { error: 'unavailable', message: 'Ollama non disponible — lancez : ollama serve' };
    }
    return { error: 'unknown', message: err.message };
  }
}

// ── Parser la réponse JSON de Llama ───────────
function parseLlamaResponse(raw, inputFallback) {
  // Nettoyer la réponse (parfois Llama ajoute du texte avant/après le JSON)
  let jsonStr = raw.trim();

  // Extraire le bloc JSON si entouré de texte
  const jsonMatch = jsonStr.match(/\{[\s\S]*\}/);
  if (jsonMatch) jsonStr = jsonMatch[0];

  try {
    const parsed = JSON.parse(jsonStr);

    // Valider et normaliser la structure
    return {
      verdict:        ['safe','warning','danger'].includes(parsed.verdict) ? parsed.verdict : 'warning',
      confidence:     Math.max(0, Math.min(100, parseInt(parsed.confidence) || 50)),
      threat_type:    parsed.threat_type    || 'suspicious',
      explanation:    parsed.explanation    || 'Analyse indisponible.',
      indicators:     Array.isArray(parsed.indicators) ? parsed.indicators.slice(0, 5) : [],
      recommendation: parsed.recommendation || 'Procédez avec prudence.',
      raw_valid: true
    };
  } catch {
    // Fallback si le JSON est invalide
    console.warn('CyberGuard: Llama returned invalid JSON, using fallback');
    return {
      verdict:        'warning',
      confidence:     40,
      threat_type:    'suspicious',
      explanation:    `Analyse de "${inputFallback.slice(0, 60)}" : résultat non structuré.`,
      indicators:     [],
      recommendation: 'Vérifiez manuellement cette URL.',
      raw_valid: false,
      raw: raw.slice(0, 200)
    };
  }
}

// ── Fusionner les 3 scores en score final ─────
function fuseScores(rulesResult, nlpResult, llamaResult) {
  // Poids : Règles 35% | NLP 25% | Llama 40%
  const WEIGHT_RULES = 0.35;
  const WEIGHT_NLP   = 0.25;
  const WEIGHT_LLAMA = 0.40;

  // Convertir les verdicts en scores numériques (0=safe, 100=danger)
  const rulesDanger  = 100 - (rulesResult?.score ?? 100);
  const nlpDanger    = nlpResult?.nlpRiskScore ?? 0;

  let llamaDanger = 0;
  if (llamaResult && !llamaResult.error) {
    const verdictMap = { safe: 0, warning: 50, danger: 90 };
    llamaDanger = verdictMap[llamaResult.verdict] ?? 50;
    // Ajuster avec la confidence
    llamaDanger = llamaDanger * (llamaResult.confidence / 100);
  }

  // Score de danger fusionné
  const fusedDanger = (
    rulesDanger  * WEIGHT_RULES +
    nlpDanger    * WEIGHT_NLP   +
    llamaDanger  * WEIGHT_LLAMA
  );

  // Convertir en score de sécurité (100 = très sûr)
  const finalScore = Math.max(0, Math.min(100, Math.round(100 - fusedDanger)));

  // Déterminer le risque final
  let finalRisk;
  if (finalScore >= 72)      finalRisk = 'safe';
  else if (finalScore >= 42) finalRisk = 'warning';
  else                        finalRisk = 'danger';

  return {
    finalScore,
    finalRisk,
    breakdown: {
      rules: Math.round(rulesDanger),
      nlp:   Math.round(nlpDanger),
      llama: Math.round(llamaDanger),
    }
  };
}

// ── Export ────────────────────────────────────
if (typeof module !== 'undefined') {
  module.exports = { analyzWithLlama, checkOllamaAvailable, checkModelAvailable, fuseScores };
}
