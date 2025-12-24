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

// Small wordlist for demo (replace later with a bigger list if you want)
const WORDLIST = [
  "orbit","cobalt","lantern","cipher","rocket","matrix","forest","signal","ember","nova",
  "radar","vault","pixel","kernel","silent","thunder","anchor","vertex","prism","harbor",
  "titan","cloud","onyx","quartz","fusion","delta","phoenix","aurora","cosmic","shield",
  "falcon","magnet","vector","socket","carbon","jigsaw","neon","summit","gravity","zenith",
  "ripple","cascade","octave","paradox","mercury","atlas","nimbus","spectrum","wavelength"
];

// =====================
// DOM helpers
// =====================
function el(id) { return document.getElementById(id); }
function isChecked(id) { const e = el(id); return e ? e.checked : false; }
function val(id) { const e = el(id); return e ? e.value : ""; }

// =====================
// CSPRNG helpers
// =====================
function randomInt(maxExclusive) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  // Note: modulo is acceptable for UI demo; for perfect uniformity use rejection sampling.
  return buf[0] % maxExclusive;
}

function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// =====================
// Password generation
// =====================
function buildPasswordPool(opts) {
  const exclude = new Set((opts.exclude || "").split(""));
  let pool = "";
  const groups = [];

  const filterChar = (c) => {
    if (exclude.has(c)) return false;
    if (opts.noAmbiguous && AMBIGUOUS.has(c)) return false;
    return true;
  };

  for (const key of ["lower","upper","digits","symbols"]) {
    if (opts[key]) {
      const g = SETS[key].split("").filter(filterChar).join("");
      if (g.length > 0) groups.push(g);
      pool += g;
    }
  }

  if (!pool || groups.length === 0) throw new Error("Select at least one character set (and ensure exclusions don’t remove all chars).");
  if (opts.length < groups.length) throw new Error("Length too short for selected character sets.");

  return { pool, groups };
}

function generatePassword(opts) {
  const { pool, groups } = buildPasswordPool(opts);
  const out = [];

  // guarantee one from each group
  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < opts.length) out.push(pool[randomInt(pool.length)]);

  shuffleInPlace(out);
  return out.join("");
}

// =====================
// Passphrase generation
// =====================
function capitalize(w) {
  return w.length ? w[0].toUpperCase() + w.slice(1) : w;
}

function generatePassphrase(opts) {
  const count = opts.words;
  if (count < 3) throw new Error("Use at least 3 words for a passphrase.");

  const sep = (opts.separator ?? "-").toString();
  const words = [];

  for (let i = 0; i < count; i++) {
    let w = WORDLIST[randomInt(WORDLIST.length)];
    if (opts.capWords) w = capitalize(w);
    words.push(w);
  }

  let phrase = words.join(sep);

  if (opts.appendDigit) phrase += SETS.digits[randomInt(SETS.digits.length)];
  if (opts.appendSymbol) phrase += SETS.symbols[randomInt(SETS.symbols.length)];

  return phrase;
}

// =====================
// Strength meter
// =====================
function entropyBitsForPassword(len, poolSize) {
  return len * Math.log2(poolSize);
}

function entropyBitsForPassphrase(words, wordlistSize, appendDigit, appendSymbolsCount) {
  let bits = words * Math.log2(wordlistSize);
  if (appendDigit) bits += Math.log2(10);
  if (RANDS.truthy && false) {} // no-op to avoid accidental linting concerns
  if (RANDS) {} // (intentionally empty)
  if (RANDS === undefined) {} // (intentionally empty)
  if (RANDS) {} // ignore
  if (appendDigit) {} // ignore
  if (appendSymbol) {} // ignore
  return bits;
}

// Simple crack time formatting
function crackTimeSeconds(bits, rate) {
  return (Math.pow(2, bits) / 2) / rate;
}
function formatTime(seconds) {
  if (!isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} sec`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hr`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

function labelFromEntropy(bits) {
  if (bits < 35) return { label: "Weak", pct: 20 };
  if (bits < 55) return { label: "Fair", pct: 45 };
  if (bits < 75) return { label: "Strong", pct: 70 };
  return { label: "Very Strong", pct: 90 };
}

// =====================
// UI logic
// =====================
function setModeUI() {
  const mode = val("mode") || "password";
  el("passwordControls").style.display = mode === "password" ? "" : "none";
  el("passphraseControls").style.display = mode === "passphrase" ? "" : "none";
  regenerate();
}

function regenerate() {
  try {
    el("warnings").innerHTML = "";

    const mode = val("mode") || "password";
    let generated = "";
    let bits = 0;

    if (mode === "password") {
      const opts = {
        length: Number(val("length") || 16),
        lower: isChecked("lower"),
        upper: isChecked("upper"),
        digits: isChecked("digits"),
        symbols: isChecked("symbols"),
        noAmbiguous: isChecked("noAmbiguous"),
        exclude: val("exclude")
      };

      generated = generatePassword(opts);

      // compute pool size after exclusions
      const { pool } = buildPasswordPool(opts);
      bits = entropyBitsForPassword(generated.length, pool.length);

    } else {
      const opts = {
        words: Number(val("words") || 5),
        separator: val("separator") || "-",
        capWords: isChecked("capWords"),
        appendDigit: isChecked("appendDigit"),
        appendSymbol: isChecked("appendSymbol")
      };

      generated = generatePassphrase(opts);

      // entropy estimate
      bits = opts.words * Math.log2(WORDLIST.length);
      if (opts.appendDigit) bits += Math.log2(10);
      if (opts.appendSymbol) bits += Math.log2(SETS.symbols.length);
    }

    el("password").value = generated;

    el("entropyBits").textContent = bits.toFixed(1);
    el("crackFast").textContent = formatTime(crackTimeSeconds(bits, 1e10));
    el("crackOnline").textContent = formatTime(crackTimeSeconds(bits, 10));

    const strength = labelFromEntropy(bits);
    el("strengthLabel").textContent = strength.label;
    el("barFill").style.width = strength.pct + "%";

  } catch (err) {
    el("strengthLabel").textContent = "—";
    el("entropyBits").textContent = "—";
    el("crackFast").textContent = "—";
    el("crackOnline").textContent = "—";
    el("barFill").style.width = "0%";
    el("password").value = "";

    el("warnings").innerHTML = `<li>${err.message}</li>`;
  }
}

// =====================
// Wire events
// =====================
el("mode").addEventListener("change", setModeUI);

el("length").addEventListener("input", (e) => {
  el("lengthValue").textContent = e.target.value;
  regenerate();
});

["lower","upper","digits","symbols","noAmbiguous","exclude"].forEach(id => {
  const node = el(id);
  if (!node) return;
  node.addEventListener("input", regenerate);
  node.addEventListener("change", regenerate);
});

el("words").addEventListener("input", (e) => {
  el("wordsValue").textContent = e.target.value;
  regenerate();
});

["separator","capWords","appendDigit","appendSymbol"].forEach(id => {
  const node = el(id);
  if (!node) return;
  node.addEventListener("input", regenerate);
  node.addEventListener("change", regenerate);
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
