// =========================
// Character sets
// =========================
const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?/|~"
};

const AMBIGUOUS = new Set(["O", "0", "I", "1", "l"]);
const SIMILAR = new Set(["{","}","[","]","(",")","/","\\","'","\"","`","~"]);

// Small built-in wordlist (portfolio demo). You can replace with a larger list later.
const WORDLIST = [
  "orbit","cobalt","lantern","cipher","rocket","matrix","forest","signal","ember","nova",
  "radar","vault","pixel","kernel","silent","thunder","anchor","vertex","prism","harbor",
  "titan","cloud","onyx","quartz","fusion","delta","phoenix","aurora","cosmic","shield",
  "falcon","magnet","vector","socket","carbon","jigsaw","neon","summit","gravity","zenith",
  "ripple","ciphered","cascade","octave","paradox","mercury","atlas","nimbus","spectrum","wavelength"
];

// =========================
// CSPRNG helpers
// =========================
function csprngUint32() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return a[0];
}

// unbiased integer in [0, maxExclusive)
function randomInt(maxExclusive) {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) throw new Error("Invalid maxExclusive");
  const maxUint32 = 0xFFFFFFFF;
  const limit = Math.floor((maxUint32 + 1) / maxExclusive) * maxExclusive;
  while (true) {
    const r = csprngUint32();
    if (r < limit) return r % maxExclusive;
  }
}

function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// =========================
// Password generation
// =========================
function buildPool(opts) {
  let pool = "";
  const groups = [];

  function addGroup(name, chars) {
    if (opts[name]) {
      groups.push(chars);
      pool += chars;
    }
  }

  addGroup("lower", SETS.lower);
  addGroup("upper", SETS.upper);
  addGroup("digits", SETS.digits);
  addGroup("symbols", SETS.symbols);

  if (groups.length === 0) throw new Error("Select at least one character set.");

  const excludeSet = new Set((opts.exclude || "").split(""));
  const filterFn = (ch) => {
    if (excludeSet.has(ch)) return false;
    if (opts.noAmbiguous && AMBIGUOUS.has(ch)) return false;
    if (opts.noSimilar && SIMILAR.has(ch)) return false;
    return true;
  };

  const filteredGroups = groups
    .map(g => g.split("").filter(filterFn).join(""))
    .filter(g => g.length > 0);

  const filteredPool = pool.split("").filter(filterFn).join("");

  if (filteredGroups.length === 0 || filteredPool.length === 0) {
    throw new Error("Exclusions removed all available characters. Adjust options.");
  }

  return { pool: filteredPool, groups: filteredGroups };
}

function generatePassword(length, opts) {
  const { pool, groups } = buildPool(opts);
  if (length < 8) throw new Error("Length must be at least 8.");
  if (length < groups.length) throw new Error("Length too short for selected categories.");

  const out = [];

  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < length) out.push(pool[randomInt(pool.length)]);

  shuffleInPlace(out);
  return out.join("");
}

// =========================
// Passphrase generation
// =========================
function capitalizeWord(w) {
  return w.length ? w[0].toUpperCase() + w.slice(1) : w;
}

function generatePassphrase(wordCount, opts) {
  if (wordCount < 3) throw new Error("Use at least 3 words for a passphrase.");
  const sep = (opts.separator ?? "-").toString();
  const words = [];

  for (let i = 0; i < wordCount; i++) {
    const w = WORDLIST[randomInt(WORDLIST.length)];
    words.push(opts.capWords ? capitalizeWord(w) : w);
  }

  let phrase = words.join(sep);

  if (opts.addDigit) phrase += SETS.digits[randomInt(SETS.digits.length)];
  if (opts.addSymbol) phrase += SETS.symbols[randomInt(SETS.symbols.length)];

  return phrase;
}

// =========================
// Strength meter
// =========================
function log2(x) { return Math.log(x) / Math.log(2); }

function hasRepeats(s) {
  return /(.)\1\1/.test(s);
}
function hasSequence(s) {
  const lower = s.toLowerCase();
  const seqs = ["abcdefghijklmnopqrstuvwxyz", "0123456789"];
  for (const seq of seqs) {
    for (let i = 0; i < seq.length - 3; i++) {
      const chunk = seq.slice(i, i + 4);
      if (lower.includes(chunk)) return true;
      if (lower.includes(chunk.split("").reverse().join(""))) return true;
    }
  }
  return false;
}
function hasKeyboardWalk(s) {
  const lower = s.toLowerCase();
  const walks = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];
  for (const w of walks) {
    for (let i = 0; i < w.length - 3; i++) {
      const chunk = w.slice(i, i + 4);
      if (lower.includes(chunk)) return true;
      if (lower.includes(chunk.split("").reverse().join(""))) return true;
    }
  }
  return false;
}
function looksLikeCommonSubstitution(s) {
  const patterns = [/@/g, /0/g, /1/g, /3/g, /\$/g, /5/g];
  const hits = patterns.reduce((acc, p) => acc + (s.match(p)?.length || 0), 0);
  return hits >= 2;
}

function formatDuration(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return "—";
  const minute = 60, hour = 3600, day = 86400, year = 31557600;
  if (seconds < minute) return `${seconds.toFixed(1)} sec`;
  if (seconds < hour) return `${(seconds / minute).toFixed(1)} min`;
  if (seconds < day) return `${(seconds / hour).toFixed(1)} hr`;
  if (seconds < year) return `${(seconds / day).toFixed(1)} days`;
  return `${(seconds / year).toFixed(1)} years`;
}

function crackTimeEstimates(entropyBits) {
  const guesses = Math.pow(2, entropyBits);
  const expectedGuesses = guesses / 2;

  const offlineFast = 1e10; // illustrative
  const online = 10;        // illustrative

  return {
    offlineFastSec: expectedGuesses / offlineFast,
    onlineSec: expectedGuesses / online
  };
}

function strengthScoreForPassword(password, opts) {
  const { pool } = buildPool(opts);
  let entropy = password.length * log2(pool.length);

  const warnings = [];
  if (password.length < 12) { warnings.push("Length under 12 characters is often inadequate for high-value accounts."); entropy -= 10; }
  if (hasRepeats(password)) { warnings.push("Repeated characters detected (e.g., 'aaa')."); entropy -= 10; }
  if (hasSequence(password)) { warnings.push("Sequential pattern detected (e.g., 'abcd' or '1234')."); entropy -= 12; }
  if (hasKeyboardWalk(password)) { warnings.push("Keyboard pattern detected (e.g., 'qwert')."); entropy -= 12; }
  if (looksLikeCommonSubstitution(password)) { warnings.push("Common substitutions detected (e.g., @ for a, 0 for o)."); entropy -= 6; }

  entropy = Math.max(0, entropy);
  return finalizeStrength(entropy, warnings);
}

function strengthScoreForPassphrase(phrase, opts) {
  // entropy ~ wordCount * log2(wordlistSize) + optional digit/symbol
  // wordCount derived from splitting on separator; conservative if separator appears in words (ours don't)
  const sep = (opts.separator ?? "-").toString();
  const words = sep ? phrase.split(sep).filter(Boolean) : phrase.split(/\s+/).filter(Boolean);
  let entropy = words.length * log2(WORDLIST.length);

  const warnings = [];
  if (words.length < 4) { warnings.push("Consider 4–6 words for stronger passphrases."); entropy -= 8; }
  if (opts.addDigit) entropy += log2(10);
  if (opts.addSymbol) entropy += log2(SETS.symbols.length);

  // penalize obvious patterns if someone types their own later (future-proof)
  if (hasSequence(phrase) || hasKeyboardWalk(phrase)) {
    warnings.push("Pattern-like sequences detected.");
    entropy -= 8;
  }

  entropy = Math.max(0, entropy);
  return finalizeStrength(entropy, warnings);
}

function finalizeStrength(entropyBits, warnings) {
  let label, pct;
  if (entropyBits < 35) { label = "Weak"; pct = 20; }
  else if (entropyBits < 55) { label = "Fair"; pct = 45; }
  else if (entropyBits < 75) { label = "Strong"; pct = 70; }
  else { label = "Very Strong"; pct = 95; }

  const times = crackTimeEstimates(entropyBits);

  return {
    entropyBits,
    label,
    pct,
    warnings,
    crackFast: formatDuration(times.offlineFastSec),
    crackOnline: formatDuration(times.onlineSec)
  };
}

// =========================
// UI wiring
// =========================
const el = (id) => document.getElementById(id);

const modeEl = el("mode");
const passwordControls = el("passwordControls");
const passphraseControls = el("passphraseControls");

const lengthEl = el("length");
const lengthValueEl = el("lengthValue");

const wordsEl = el("words");
const wordsValueEl = el("wordsValue");
const separatorEl = el("separator");
const capWordsEl = el("capWords");
const addDigitEl = el("addDigit");
const addSymbolEl = el("addSymbol");

const pwEl = el("password");
const warningsEl = el("warnings");
const strengthLabelEl = el("strengthLabel");
const barFillEl = el("barFill");
const entropyBitsEl = el("entropyBits");
const crackFastEl = el("crackFast");
const crackOnlineEl = el("crackOnline");
const copyStatusEl = el("copyStatus");

function getPasswordOptions() {
  return {
    lower: el("lower").checked,
    upper: el("upper").checked,
    digits: el("digits").checked,
    symbols: el("symbols").checked,
    noAmbiguous: el("noAmbiguous").checked,
    noSimilar: el("noSimilar").checked,
    exclude: el("exclude").value || ""
  };
}

function getPassphraseOptions() {
  return {
    separator: separatorEl.value ?? "-",
    capWords: capWordsEl.checked,
    addDigit: addDigitEl.checked,
    addSymbol: addSymbolEl.checked
  };
}

function renderStrength(result) {
  strengthLabelEl.textContent = result.label;
  barFillEl.style.width = `${result.pct}%`;
  entropyBitsEl.textContent = result.entropyBits.toFixed(1);
  crackFastEl.textContent = result.crackFast;
  crackOnlineEl.textContent = result.crackOnline;

  warningsEl.innerHTML = "";
  for (const w of result.warnings) {
    const li = document.createElement("li");
    li.textContent = w;
    warningsEl.appendChild(li);
  }
}

function regenerate() {
  copyStatusEl.textContent = "";
  const mode = modeEl.value;

  try {
    let generated;
    let strength;

    if (mode === "password") {
      const opts = getPasswordOptions();
      const len = parseInt(lengthEl.value, 10);
      generated = generatePassword(len, opts);
      strength = strengthScoreForPassword(generated, opts);
    } else {
      const opts = getPassphraseOptions();
      const wc = parseInt(wordsEl.value, 10);
      generated = generatePassphrase(wc, opts);
      strength = strengthScoreForPassphrase(generated, opts);
    }

    pwEl.value = generated;
    renderStrength(strength);
  } catch (e) {
    pwEl.value = "";
    strengthLabelEl.textContent = "—";
    barFillEl.style.width = `0%`;
    entropyBitsEl.textContent = "—";
    crackFastEl.textContent = "—";
    crackOnlineEl.textContent = "—";
    warningsEl.innerHTML = "";
    const li = document.createElement("li");
    li.textContent = e.message;
    warningsEl.appendChild(li);
  }
}

function setModeUI() {
  const mode = modeEl.value;
  passwordControls.style.display = mode === "password" ? "" : "none";
  passphraseControls.style.display = mode === "passphrase" ? "" : "none";
  regenerate();
}

// Events
modeEl.addEventListener("change", setModeUI);

lengthEl.addEventListener("input", () => {
  lengthValueEl.textContent = lengthEl.value;
  regenerate();
});
["lower","upper","digits","symbols","noAmbiguous","noSimilar","exclude"].forEach(id => {
  el(id).addEventListener("input", regenerate);
});

wordsEl.addEventListener("input", () => {
  wordsValueEl.textContent = wordsEl.value;
  regenerate();
});
[separatorEl, capWordsEl, addDigitEl, addSymbolEl].forEach(node => {
  node.addEventListener("input", regenerate);
});

el("regen").addEventListener("click", regenerate);

el("toggle").addEventListener("click", () => {
  const isHidden = pwEl.type === "password";
  pwEl.type = isHidden ? "text" : "password";
  el("toggle").textContent = isHidden ? "Hide" : "Show";
});

el("copy").addEventListener("click", async () => {
  if (!pwEl.value) return;
  try {
    await navigator.clipboard.writeText(pwEl.value);
    copyStatusEl.textContent = "Copied to clipboard.";
    setTimeout(() => (copyStatusEl.textContent = ""), 1500);
  } catch {
    copyStatusEl.textContent = "Copy failed (browser permissions).";
  }
});

// init
lengthValueEl.textContent = lengthEl.value;
wordsValueEl.textContent = wordsEl.value;
setModeUI();
