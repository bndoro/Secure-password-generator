// =====================
// Character sets
// =====================
const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?"
};

const AMBIGUOUS = new Set(["O", "0", "I", "1", "l"]);

// Built-in fallback wordlist (expand later if you want)
const DEFAULT_WORDLIST = [
  "quiet","brave","rapid","gentle","silent","bright","blue","green","cosmic","secure",
  "orbit","cobalt","lantern","cipher","rocket","matrix","forest","signal","ember","nova",
  "radar","vault","pixel","kernel","thunder","anchor","vertex","prism","harbor","titan",
  "cloud","onyx","quartz","fusion","delta","phoenix","aurora","shield","falcon","vector",
  "socket","carbon","jigsaw","neon","summit","gravity","zenith","ripple","cascade","octave",
  "paradox","mercury","atlas","nimbus","spectrum","wavelength","firewall","packet","token",
  "hash","salt","harden","monitor","detect","response","policy","access","audit","backup",
  "endpoint","incident","alert","threat","defense"
];

// Simple glue words for sentence templates
const GLUE = {
  determiners: ["the", "a", "this"],
  preps: ["over", "under", "near", "beyond", "within", "around"],
  verbs: ["moves", "guards", "protects", "shifts", "drifts", "covers", "secures", "tests"],
  adverbs: ["quietly", "swiftly", "carefully", "boldly"]
};

// =====================
// DOM helpers
// =====================
function el(id){ return document.getElementById(id); }
function isChecked(id){ const e = el(id); return e ? e.checked : false; }
function val(id){ const e = el(id); return e ? e.value : ""; }

// =====================
// CSPRNG helpers
// =====================
function randomInt(maxExclusive){
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % maxExclusive;
}

function shuffle(arr){
  for (let i = arr.length - 1; i > 0; i--){
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// =====================
// No-repeat tracking (hashed)
// =====================
const sessionSeen = new Set();

function fnv1a32(str){
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++){
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

function makeHistoryKey(scope){
  return `pwgen_history_${scope}`;
}

function loadHistory(scope){
  const key = makeHistoryKey(scope);
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return new Set();
    return new Set(arr);
  } catch {
    return new Set();
  }
}

function saveHistory(scope, set){
  const key = makeHistoryKey(scope);
  const MAX = 4000;
  const arr = Array.from(set);
  const trimmed = arr.length > MAX ? arr.slice(arr.length - MAX) : arr;
  localStorage.setItem(key, JSON.stringify(trimmed));
}

function computeScopeFingerprint(mode, effectiveWordlist){
  const wl = effectiveWordlist.map(w => w.toLowerCase()).sort().join(",");
  return `${mode}_${fnv1a32(wl)}`;
}

function isRepeat(candidate, scope, noRepeatEnabled){
  if (!noRepeatEnabled) return false;
  const hash = fnv1a32(candidate);
  if (sessionSeen.has(`${scope}:${hash}`)) return true;

  const persisted = loadHistory(scope);
  if (persisted.has(hash)) return true;

  return false;
}

function remember(candidate, scope, noRepeatEnabled){
  if (!noRepeatEnabled) return;
  const hash = fnv1a32(candidate);
  sessionSeen.add(`${scope}:${hash}`);

  const persisted = loadHistory(scope);
  persisted.add(hash);
  saveHistory(scope, persisted);
}

// =====================
// PASSWORD MODE
// =====================
function buildPasswordPool(opts){
  const exclude = new Set((opts.exclude || "").split(""));
  const groups = [];
  let pool = "";

  const keep = (c) => {
    if (exclude.has(c)) return false;
    if (opts.noAmbiguous && AMBIGUOUS.has(c)) return false;
    return true;
  };

  for (const key of ["lower","upper","digits","symbols"]){
    if (!opts[key]) continue;
    const g = SETS[key].split("").filter(keep).join("");
    if (g.length === 0) continue;
    groups.push(g);
    pool += g;
  }

  if (!pool || groups.length === 0) {
    throw new Error("Select at least one character set (and ensure exclusions don’t remove all chars).");
  }
  if (opts.length < groups.length) {
    throw new Error("Length too short for selected character sets.");
  }
  return { pool, groups };
}

function generatePasswordOnce(opts){
  const { pool, groups } = buildPasswordPool(opts);
  const out = [];

  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < opts.length) out.push(pool[randomInt(pool.length)]);

  shuffle(out);
  return { value: out.join(""), poolSize: pool.length };
}

function generatePasswordNoRepeat(opts, noRepeatEnabled){
  const { pool } = buildPasswordPool(opts);
  const scope = `password_${fnv1a32(pool)}`;

  const MAX_TRIES = 200;
  for (let i = 0; i < MAX_TRIES; i++){
    const out = generatePasswordOnce(opts);
    if (!isRepeat(out.value, scope, noRepeatEnabled)){
      remember(out.value, scope, noRepeatEnabled);
      return out;
    }
  }
  throw new Error("Could not find a new unique password. Change length/options to expand the search space.");
}

// =====================
// PASSPHRASE MODE (sentence-style + custom/fallback)
// =====================
function parseCustomWords(text){
  const raw = text
    .split(/[\n,]+/g)
    .map(w => w.trim())
    .filter(Boolean);

  const seen = new Set();
  const words = [];
  for (const w of raw){
    const k = w.toLowerCase();
    if (!seen.has(k)){
      seen.add(k);
      words.push(w);
    }
  }
  return words;
}

function capFirst(w){
  return w.length ? w[0].toUpperCase() + w.slice(1) : w;
}

function pickFrom(list){
  return list[randomInt(list.length)];
}

function pickWords({ wordCount, list, allowRepeats }){
  if (!allowRepeats && wordCount > list.length){
    throw new Error("Not enough unique words for that count. Turn on 'Allow repeats' or add more words.");
  }

  const chosen = [];
  const available = [...list];

  for (let i = 0; i < wordCount; i++){
    const source = allowRepeats ? list : available;
    const pick = pickFrom(source);
    chosen.push(pick);

    if (!allowRepeats){
      const idx = available.indexOf(pick);
      if (idx >= 0) available.splice(idx, 1);
    }
  }
  return chosen;
}

// Short/Medium/Long sentence templates
function makeSentence(chosenWords, opts){
  const words = [...chosenWords];

  // Ensure enough words exist for templates
  while (words.length < 6) words.push(pickFrom(chosenWords));

  const det1 = pickFrom(GLUE.determiners);
  const det2 = pickFrom(GLUE.determiners);
  const prep = pickFrom(GLUE.preps);
  const verb = pickFrom(GLUE.verbs);
  const adv = pickFrom(GLUE.adverbs);

  let sentence = "";

  if (opts.sentenceLen === "short") {
    // 4 content words
    // "The W1 W2 verb the W3 W4."
    sentence = `${det1} ${words[0]} ${words[1]} ${verb} ${det2} ${words[2]} ${words[3]}.`;
  } else if (opts.sentenceLen === "medium") {
    // 4 content words + glue
    // "The W1 W2 verb adv prep the W3 W4."
    sentence = `${det1} ${words[0]} ${words[1]} ${verb} ${adv} ${prep} ${det2} ${words[2]} ${words[3]}.`;
  } else {
    // long (still capped): 5 content words
    // "The W1 W2 verb adv prep the W3 W4 W5."
    sentence = `${det1} ${words[0]} ${words[1]} ${verb} ${adv} ${prep} ${det2} ${words[2]} ${words[3]} ${words[4]}.`;
  }

  if (opts.capFirstWord) sentence = capFirst(sentence);
  return sentence;
}

function makeJoinPassphrase(chosenWords, opts){
  const sep = (opts.separator ?? "-").toString();
  let phrase = chosenWords.join(sep);
  if (opts.capFirstWord && chosenWords.length > 0){
    const parts = phrase.split(sep);
    parts[0] = capFirst(parts[0]);
    phrase = parts.join(sep);
  }
  return phrase;
}

function generatePassphraseOnce(opts){
  const custom = parseCustomWords(opts.customWords || "");
  const useCustomOnly = opts.useCustomOnly;

  let listToUse;
  let sourceName;

  if (custom.length > 0){
    listToUse = custom;
    sourceName = "custom";
  } else {
    if (useCustomOnly){
      throw new Error("You enabled 'Use my words only' but provided no words.");
    }
    listToUse = DEFAULT_WORDLIST;
    sourceName = "built-in";
  }

  if (listToUse.length < 2){
    throw new Error("Wordlist is too small. Add more words.");
  }

  const chosen = pickWords({
    wordCount: opts.words,
    list: listToUse,
    allowRepeats: opts.allowRepeats
  });

  let base;
  if (opts.sentenceMode){
    base = makeSentence(chosen, { capFirstWord: opts.capWords, sentenceLen: opts.sentenceLen });
  } else {
    base = makeJoinPassphrase(chosen, { separator: opts.separator, capFirstWord: opts.capWords });
  }

  let finalValue = base;
  if (opts.appendDigit) finalValue += SETS.digits[randomInt(SETS.digits.length)];
  if (opts.appendSymbol) finalValue += SETS.symbols[randomInt(SETS.symbols.length)];

  return { value: finalValue, wordlistSize: listToUse.length, sourceName, effectiveWordlist: listToUse };
}

function generatePassphraseNoRepeat(opts){
  const temp = generatePassphraseOnce(opts);
  const scope = computeScopeFingerprint("passphrase", temp.effectiveWordlist);
  const noRepeatEnabled = opts.noRepeat;

  const MAX_TRIES = 250;
  for (let i = 0; i < MAX_TRIES; i++){
    const out = generatePassphraseOnce(opts);
    if (!isRepeat(out.value, scope, noRepeatEnabled)){
      remember(out.value, scope, noRepeatEnabled);
      return out;
    }
  }
  throw new Error("Could not find a new unique passphrase. Add more words or allow repeats to expand the space.");
}

// =====================
// Strength + crack time (estimates)
// =====================
function entropyPassword(len, poolSize){
  return len * Math.log2(poolSize);
}

function entropyPassphrase(wordCount, wordlistSize, addDigit, addSymbol){
  let bits = wordCount * Math.log2(wordlistSize);
  if (addDigit) bits += Math.log2(10);
  if (addSymbol) bits += Math.log2(SETS.symbols.length);
  return bits;
}

function crackSeconds(bits, rate){
  return (Math.pow(2, bits) / 2) / rate;
}

function fmt(seconds){
  if (!isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} sec`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hr`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

function label(bits){
  if (bits < 35) return { label: "Weak", pct: 20 };
  if (bits < 55) return { label: "Fair", pct: 45 };
  if (bits < 75) return { label: "Strong", pct: 70 };
  return { label: "Very Strong", pct: 90 };
}

// =====================
// UI
// =====================
function setModeUI(){
  const mode = val("mode") || "password";
  el("passwordControls").style.display = mode === "password" ? "" : "none";
  el("passphraseControls").style.display = mode === "passphrase" ? "" : "none";
  regenerate();
}

function regenerate(){
  try{
    el("warnings").innerHTML = "";
    el("copyStatus").textContent = "";

    const mode = val("mode") || "password";
    let out, bits;

    if (mode === "password"){
      const opts = {
        length: Number(val("length") || 16),
        lower: isChecked("lower"),
        upper: isChecked("upper"),
        digits: isChecked("digits"),
        symbols: isChecked("symbols"),
        noAmbiguous: isChecked("noAmbiguous"),
        exclude: val("exclude")
      };

      out = generatePasswordNoRepeat(opts, true);
      bits = entropyPassword(out.value.length, out.poolSize);

    } else {
      const opts = {
        customWords: val("customWords"),
        useCustomOnly: isChecked("useCustomOnly"),
        sentenceMode: isChecked("sentenceMode"),
        sentenceLen: val("sentenceLen") || "short",
        words: Number(val("words") || 6),
        separator: val("separator") || "-",
        capWords: isChecked("capWords"),
        appendDigit: isChecked("appendDigit"),
        appendSymbol: isChecked("appendSymbol"),
        allowRepeats: isChecked("allowRepeats"),
        noRepeat: isChecked("noRepeat")
      };

      out = generatePassphraseNoRepeat(opts);
      bits = entropyPassphrase(opts.words, out.wordlistSize, opts.appendDigit, opts.appendSymbol);

      const sourceMsg = out.sourceName === "custom"
        ? `Using your words (${out.wordlistSize} unique).`
        : `Using built-in words (${out.wordlistSize}).`;

      el("warnings").innerHTML = `<li>${sourceMsg} Sentence length: ${opts.sentenceLen}.</li>`;
    }

    el("password").value = out.value;

    el("entropyBits").textContent = bits.toFixed(1);
    el("crackFast").textContent = fmt(crackSeconds(bits, 1e10));
    el("crackOnline").textContent = fmt(crackSeconds(bits, 10));

    const s = label(bits);
    el("strengthLabel").textContent = s.label;
    el("barFill").style.width = s.pct + "%";

  } catch (err){
    el("password").value = "";
    el("strengthLabel").textContent = "—";
    el("entropyBits").textContent = "—";
    el("crackFast").textContent = "—";
    el("crackOnline").textContent = "—";
    el("barFill").style.width = "0%";
    el("warnings").innerHTML = `<li>${err.message}</li>`;
  }
}

// =====================
// Events
// =====================
el("mode").addEventListener("change", setModeUI);

el("length").addEventListener("input", (e) => {
  el("lengthValue").textContent = e.target.value;
  regenerate();
});

["lower","upper","digits","symbols","noAmbiguous","exclude"].forEach(id => {
  const n = el(id);
  if (!n) return;
  n.addEventListener("input", regenerate);
  n.addEventListener("change", regenerate);
});

el("words").addEventListener("input", (e) => {
  el("wordsValue").textContent = e.target.value;
  regenerate();
});

["customWords","useCustomOnly","sentenceMode","sentenceLen","separator","capWords","appendDigit","appendSymbol","allowRepeats","noRepeat"].forEach(id => {
  const n = el(id);
  if (!n) return;
  n.addEventListener("input", regenerate);
  n.addEventListener("change", regenerate);
});

el("regen").addEventListener("click", regenerate);

el("toggle").addEventListener("click", () => {
  const pw = el("password");
  pw.type = pw.type === "password" ? "text" : "password";
  el("toggle").textContent = pw.type === "password" ? "Show" : "Hide";
});

el("copy").addEventListener("click", () => {
  const txt = el("password").value;
  if (!txt) return;
  navigator.clipboard.writeText(txt);
  el("copyStatus").textContent = "Copied!";
  setTimeout(() => el("copyStatus").textContent = "", 1200);
});

// init
el("lengthValue").textContent = val("length") || "16";
el("wordsValue").textContent = val("words") || "6";
setModeUI();
