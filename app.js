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
  "orbit","cobalt","lantern","cipher","rocket","matrix","forest","signal","ember","nova",
  "radar","vault","pixel","kernel","silent","thunder","anchor","vertex","prism","harbor",
  "titan","cloud","onyx","quartz","fusion","delta","phoenix","aurora","cosmic","shield",
  "falcon","magnet","vector","socket","carbon","jigsaw","neon","summit","gravity","zenith",
  "ripple","cascade","octave","paradox","mercury","atlas","nimbus","spectrum","wavelength",
  "safeguard","firewall","packet","token","hash","salt","harden","monitor","detect","response",
  "secure","policy","access","audit","backup","endpoint","incident","alert","threat","defense"
];

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
  return buf[0] % maxExclusive; // UI-grade; upgrade to rejection sampling if you want perfect uniformity
}

function shuffle(arr){
  for (let i = arr.length - 1; i > 0; i--){
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
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

function generatePassword(opts){
  const { pool, groups } = buildPasswordPool(opts);
  const out = [];

  // Ensure at least one per selected group
  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < opts.length) out.push(pool[randomInt(pool.length)]);

  shuffle(out);
  return { value: out.join(""), poolSize: pool.length };
}

// =====================
// PASSPHRASE MODE (custom OR fallback)
// =====================
function parseCustomWords(text){
  const raw = text
    .split(/[\n,]+/g)
    .map(w => w.trim())
    .filter(Boolean);

  // dedupe case-insensitively
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

function cap(w){
  return w.length ? w[0].toUpperCase() + w.slice(1) : w;
}

function pickWords({ wordCount, list, allowRepeats, capWords, separator }){
  if (!allowRepeats && wordCount > list.length){
    throw new Error("Not enough unique words for that count. Turn on 'Allow repeats' or add more words.");
  }

  const chosen = [];
  const available = [...list];

  for (let i = 0; i < wordCount; i++){
    const source = allowRepeats ? list : available;
    const pick = source[randomInt(source.length)];
    chosen.push(capWords ? cap(pick) : pick);

    if (!allowRepeats){
      const idx = available.indexOf(pick);
      if (idx >= 0) available.splice(idx, 1);
    }
  }

  return chosen.join(separator);
}

function generatePassphrase(opts){
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

  const phrase = pickWords({
    wordCount: opts.words,
    list: listToUse,
    allowRepeats: opts.allowRepeats,
    capWords: opts.capWords,
    separator: opts.separator
  });

  let finalValue = phrase;
  if (opts.appendDigit) finalValue += SETS.digits[randomInt(SETS.digits.length)];
  if (opts.appendSymbol) finalValue += SETS.symbols[randomInt(SETS.symbols.length)];

  return { value: finalValue, wordlistSize: listToUse.length, sourceName };
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

      out = generatePassword(opts);
      bits = entropyPassword(out.value.length, out.poolSize);

    } else {
      const opts = {
        customWords: val("customWords"),
        useCustomOnly: isChecked("useCustomOnly"),
        words: Number(val("words") || 5),
        separator: val("separator") || "-",
        capWords: isChecked("capWords"),
        appendDigit: isChecked("appendDigit"),
        appendSymbol: isChecked("appendSymbol"),
        allowRepeats: isChecked("allowRepeats")
      };

      out = generatePassphrase(opts);
      bits = entropyPassphrase(opts.words, out.wordlistSize, opts.appendDigit, opts.appendSymbol);

      const sourceMsg = out.sourceName === "custom"
        ? `Using your custom list (${out.wordlistSize} unique words).`
        : `Using built-in list (${out.wordlistSize} words).`;

      let extra = "";
      if (out.sourceName === "custom" && out.wordlistSize < 20){
        extra = " Add more words for stronger passphrases.";
      }

      el("warnings").innerHTML = `<li>${sourceMsg}${extra}</li>`;
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

["customWords","useCustomOnly","separator","capWords","appendDigit","appendSymbol","allowRepeats"].forEach(id => {
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
el("wordsValue").textContent = val("words") || "5";
setModeUI();
