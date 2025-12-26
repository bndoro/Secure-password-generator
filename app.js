const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?"
};

const AMBIGUOUS = new Set(["O", "0", "I", "1", "l"]);

function el(id){ return document.getElementById(id); }
function isChecked(id){ const e = el(id); return e ? e.checked : false; }
function val(id){ const e = el(id); return e ? e.value : ""; }

// CSPRNG
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

// ---------- PASSWORD MODE ----------
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

  if (!pool || groups.length === 0) throw new Error("Select at least one character set (and ensure exclusions don’t remove all chars).");
  if (opts.length < groups.length) throw new Error("Length too short for selected character sets.");
  return { pool, groups };
}

function generatePassword(opts){
  const { pool, groups } = buildPasswordPool(opts);
  const out = [];

  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < opts.length) out.push(pool[randomInt(pool.length)]);

  shuffle(out);
  return { value: out.join(""), poolSize: pool.length };
}

// ---------- PASSPHRASE MODE (YOUR WORDS) ----------
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

function generatePassphrase(opts){
  const list = parseCustomWords(opts.customWords);
  if (list.length < 2) throw new Error("Add at least 2 words to your list (one per line or comma-separated).");

  const count = opts.words;
  if (!opts.allowRepeats && count > list.length){
    throw new Error("Not enough unique words for that count. Turn on 'Allow repeats' or add more words.");
  }

  const chosen = [];
  const available = [...list];

  for (let i = 0; i < count; i++){
    const source = opts.allowRepeats ? list : available;
    const pick = source[randomInt(source.length)];
    chosen.push(opts.capWords ? cap(pick) : pick);

    if (!opts.allowRepeats){
      const idx = available.indexOf(pick);
      if (idx >= 0) available.splice(idx, 1);
    }
  }

  let phrase = chosen.join(opts.separator);

  if (opts.appendDigit) phrase += SETS.digits[randomInt(SETS.digits.length)];
  if (opts.appendSymbol) phrase += SETS.symbols[randomInt(SETS.symbols.length)];

  return { value: phrase, wordlistSize: list.length };
}

// ---------- STRENGTH ----------
function entropyPassword(len, poolSize){ return len * Math.log2(poolSize); }
function entropyPassphrase(wordCount, wordlistSize, addDigit, addSymbol){
  let bits = wordCount * Math.log2(wordlistSize);
  if (addDigit) bits += Math.log2(10);
  if (addSymbol) bits += Math.log2(SETS.symbols.length);
  return bits;
}
function crackSeconds(bits, rate){ return (Math.pow(2, bits) / 2) / rate; }
function fmt(seconds){
  if (!isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} sec`;
  if (seconds < 3600) return `${(seconds/60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds/3600).toFixed(1)} hr`;
  return `${(seconds/86400).toFixed(1)} days`;
}
function label(bits){
  if (bits < 35) return { label:"Weak", pct:20 };
  if (bits < 55) return { label:"Fair", pct:45 };
  if (bits < 75) return { label:"Strong", pct:70 };
  return { label:"Very Strong", pct:90 };
}

// ---------- UI ----------
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
        words: Number(val("words") || 5),
        separator: val("separator") || "-",
        capWords: isChecked("capWords"),
        appendDigit: isChecked("appendDigit"),
        appendSymbol: isChecked("appendSymbol"),
        allowRepeats: isChecked("allowRepeats")
      };
      out = generatePassphrase(opts);
      bits = entropyPassphrase(opts.words, out.wordlistSize, opts.appendDigit, opts.appendSymbol);

      if (out.wordlistSize < 20){
        el("warnings").innerHTML = `<li>Your word list is small (${out.wordlistSize}). Add more words for stronger passphrases.</li>`;
      }
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

// Events
el("mode").addEventListener("change", setModeUI);

el("length").addEventListener("input", (e) => {
  el("lengthValue").textContent = e.target.value;
  regenerate();
});
["lower","upper","digits","symbols","noAmbiguous","exclude"].forEach(id => {
  const n = el(id);
  if (!n) return;
  n.addEventListener("input"
