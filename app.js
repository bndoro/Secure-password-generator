// =====================
// Policy configuration
// =====================
const POLICY = {
  minLen: 12,
  maxLen: 32,
  // Must have at least 3 of these 4:
  groups: ["upper", "lower", "digits", "symbols"],
  specials: "~`!#$%*()_+-={}[]:';?,./", // per your requirement list (no quotes, but we include ')
};

// Example banned list; expand anytime.
const BANNED_WORDS = [
  "password", "rowdy", "qwerty", "letmein", "admin", "welcome", "iloveyou"
];

// =====================
// Character sets
// =====================
const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: POLICY.specials,
  space: " "
};

const AMBIGUOUS = new Set(["O", "0", "I", "1", "l"]);

// Built-in uncommon words (fallback)
const DEFAULT_WORDLIST = [
  "cobalt","lantern","cipher","rocket","matrix","ember","nova","radar","vault","pixel",
  "kernel","anchor","vertex","prism","harbor","titan","onyx","quartz","fusion","phoenix",
  "aurora","falcon","vector","socket","carbon","jigsaw","neon","summit","gravity","zenith",
  "ripple","cascade","octave","paradox","mercury","atlas","nimbus","spectrum","wavelength",
  "firewall","packet","token","hash","salt","harden","monitor","detect","response",
  "policy","access","audit","backup","endpoint","incident","alert","threat","defense",
  "cord","tack","bramble","saffron","mosaic","thimble","anvil","lattice","emberglow"
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
  try {
    const raw = localStorage.getItem(makeHistoryKey(scope));
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? new Set(arr) : new Set();
  } catch {
    return new Set();
  }
}

function saveHistory(scope, set){
  const MAX = 4000;
  const arr = Array.from(set);
  const trimmed = arr.length > MAX ? arr.slice(arr.length - MAX) : arr;
  localStorage.setItem(makeHistoryKey(scope), JSON.stringify(trimmed));
}

function isRepeat(candidate, scope, enabled){
  if (!enabled) return false;
  const hash = fnv1a32(candidate);
  if (sessionSeen.has(`${scope}:${hash}`)) return true;
  const persisted = loadHistory(scope);
  return persisted.has(hash);
}

function remember(candidate, scope, enabled){
  if (!enabled) return;
  const hash = fnv1a32(candidate);
  sessionSeen.add(`${scope}:${hash}`);
  const persisted = loadHistory(scope);
  persisted.add(hash);
  saveHistory(scope, persisted);
}

// =====================
// Utilities: policy checks
// =====================
function normalizeForWordScan(s){
  // Convert to lowercase and split on non-letters/numbers to catch embedded words.
  return s.toLowerCase();
}

function containsBannedWord(s){
  const x = normalizeForWordScan(s);
  for (const w of BANNED_WORDS){
    if (w && x.includes(w)) return w;
  }
  return null;
}

function containsPersonalInfo(s, name, birth){
  const x = s.toLowerCase();
  const hits = [];

  const n = (name || "").trim().toLowerCase();
  if (n && n.length >= 3 && x.includes(n)) hits.push(`name/username (“${name}”)`);

  const b = (birth || "").trim().toLowerCase();
  if (b && b.length >= 2 && x.includes(b)) hits.push(`birth info (“${birth}”)`);

  return hits;
}

function countGroupsPresent(s){
  let present = 0;

  const hasUpper = /[A-Z]/.test(s);
  const hasLower = /[a-z]/.test(s);
  const hasDigit = /[0-9]/.test(s);
  const hasSymbol = new RegExp("[" + escapeForCharClass(POLICY.specials) + "]").test(s);

  if (hasUpper) present++;
  if (hasLower) present++;
  if (hasDigit) present++;
  if (hasSymbol) present++;

  return { present, hasUpper, hasLower, hasDigit, hasSymbol };
}

function escapeForCharClass(chars){
  // Escape special regex class chars: \ - ] ^
  return chars.replace(/[-\\\]^\n]/g, "\\$&");
}

function validatePolicy(s){
  const errs = [];

  if (s.length < POLICY.minLen) errs.push(`Too short: minimum ${POLICY.minLen} characters.`);
  if (s.length > POLICY.maxLen) errs.push(`Too long: maximum ${POLICY.maxLen} characters.`);

  // spaces allowed but not at beginning or end
  if (s.startsWith(" ") || s.endsWith(" ")) errs.push("Spaces are not allowed at the beginning or end.");

  const g = countGroupsPresent(s);
  if (g.present < 3) errs.push("Must include at least 3 of 4 groups: uppercase, lowercase, digits, special characters.");

  return errs;
}

// =====================
// PASSWORD MODE generator
// =====================
function buildPasswordPool(opts){
  const exclude = new Set((opts.exclude || "").split(""));
  const groups = [];
  let pool = "";

  const keep = (c) => {
    if (exclude.has(c)) return false;
    if (opts.noAmbiguous && AMBIGUOUS.has(c)) return false;
    // if spaces not allowed, drop them
    if (c === " " && !opts.allowSpaces) return false;
    return true;
  };

  // Enforce: user must select at least 3 of 4 groups for password mode
  const selectedGroups = ["upper","lower","digits","symbols"].filter(k => opts[k]);
  if (selectedGroups.length < 3){
    throw new Error("Policy requires at least 3 of 4 groups. Select at least three: upper, lower, digits, special.");
  }

  for (const key of ["lower","upper","digits","symbols"]){
    if (!opts[key]) continue;
    const g = SETS[key].split("").filter(keep).join("");
    if (g.length === 0) continue;
    groups.push(g);
    pool += g;
  }

  // Optional: add spaces into pool (NOT required for group count)
  if (opts.allowSpaces){
    const spaceOk = keep(" ");
    if (spaceOk){
      pool += " ";
    }
  }

  if (!pool || groups.length === 0) {
    throw new Error("No valid characters available. Adjust options or exclusions.");
  }

  // Ensure length can satisfy group guarantees
  if (opts.length < groups.length) {
    throw new Error("Length too short for the selected groups.");
  }

  return { pool, groups };
}

function generatePasswordOnce(opts){
  const { pool, groups } = buildPasswordPool(opts);
  const out = [];

  // One char from each required group (upper/lower/digit/symbol as selected)
  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < opts.length) out.push(pool[randomInt(pool.length)]);

  shuffle(out);

  // Fix policy: no space at start/end
  // If we allowed spaces, swap any edge space with a non-space character.
  if (out[0] === " " || out[out.length - 1] === " "){
    for (let i = 1; i < out.length - 1; i++){
      if (out[i] !== " "){
        if (out[0] === " "){ [out[0], out[i]] = [out[i], out[0]]; }
        if (out[out.length - 1] === " "){ [out[out.length - 1], out[i]] = [out[i], out[out.length - 1]]; }
        break;
      }
    }
    // If still edge spaces (rare), just replace them with a symbol
    if (out[0] === " ") out[0] = SETS.symbols[randomInt(SETS.symbols.length)];
    if (out[out.length - 1] === " ") out[out.length - 1] = SETS.symbols[randomInt(SETS.symbols.length)];
  }

  return { value: out.join(""), poolSize: pool.length };
}

function generatePasswordNoRepeat(opts){
  const scope = `password_${fnv1a32(JSON.stringify({
    length: opts.length,
    lower: opts.lower, upper: opts.upper, digits: opts.digits, symbols: opts.symbols,
    allowSpaces: opts.allowSpaces,
    exclude: opts.exclude,
    noAmbiguous: opts.noAmbiguous,
    blockBanned: opts.blockBanned
  }))}`;

  const MAX_TRIES = 400;
  for (let i = 0; i < MAX_TRIES; i++){
    const out = generatePasswordOnce(opts);

    if (opts.blockBanned){
      const bad = containsBannedWord(out.value);
      if (bad) continue;
    }

    const policyErrs = validatePolicy(out.value);
    if (policyErrs.length) continue;

    if (!isRepeat(out.value, scope, opts.noRepeat)) {
      remember(out.value, scope, opts.noRepeat);
      return out;
    }
  }

  throw new Error("Could not find a compliant, unique password. Try a different length or adjust options/exclusions.");
}

// =====================
// PASSPHRASE MODE generator
// =====================
function parseWords(text){
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

function capFirstWord(w){
  return w.length ? w[0].toUpperCase() + w.slice(1) : w;
}

function pickFrom(list){
  return list[randomInt(list.length)];
}

function pickWords({ wordCount, list, allowRepeats }){
  if (!allowRepeats && wordCount > list.length){
    throw new Error("Not enough unique words. Turn on 'Allow word reuse' or add more words.");
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

function filterBannedWordsFromList(list){
  return list.filter(w => !containsBannedWord(w));
}

function buildPassphrase(chosen, style){
  // Make passphrases students can remember, like examples you gave.
  const words = chosen.map(w => capFirstWord(w));

  if (style === "camel") {
    // BirdsSwimCoffeePurple
    return words.join("");
  }
  if (style === "underscore") {
    // BirdsSwimCoffee_Purple (underscore before last word)
    if (words.length <= 1) return words.join("");
    return words.slice(0, -1).join("") + "_" + words[words.length - 1];
  }
  // spaced: Birds Swim Coffee Purple
  return words.join(" ");
}

function ensureDigitAndSpecial(passphrase, ensureDigit, ensureSpecial){
  let out = passphrase;

  // Ensure digit
  if (ensureDigit && !/[0-9]/.test(out)){
    out += SETS.digits[randomInt(SETS.digits.length)];
  }

  // Ensure special
  const symRe = new RegExp("[" + escapeForCharClass(POLICY.specials) + "]");
  if (ensureSpecial && !symRe.test(out)){
    out += SETS.symbols[randomInt(SETS.symbols.length)];
  }

  // No leading/trailing spaces
  out = out.trim();

  return out;
}

function generatePassphraseNoRepeat(opts){
  const custom = parseWords(opts.customWords || "");
  let listToUse;
  let sourceName;

  if (custom.length > 0){
    listToUse = custom;
    sourceName = "custom";
  } else {
    if (opts.useCustomOnly){
      throw new Error("You enabled 'Use my words only' but provided no words.");
    }
    listToUse = DEFAULT_WORDLIST;
    sourceName = "built-in";
  }

  if (opts.blockBanned){
    const filtered = filterBannedWordsFromList(listToUse);
    if (filtered.length < 3){
      throw new Error("After blocking not-allowed words, the wordlist is too small. Add more words.");
    }
    listToUse = filtered;
  }

  const scope = `passphrase_${fnv1a32(JSON.stringify({
    style: opts.style,
    words: opts.words,
    ensureDigit: opts.ensureDigit,
    ensureSpecial: opts.ensureSpecial,
    useCustomOnly: opts.useCustomOnly,
    sourceName,
    listHash: fnv1a32(listToUse.map(w => w.toLowerCase()).sort().join(",")),
    blockBanned: opts.blockBanned
  }))}`;

  const MAX_TRIES = 400;
  for (let i = 0; i < MAX_TRIES; i++){
    const chosen = pickWords({ wordCount: opts.words, list: listToUse, allowRepeats: opts.allowRepeats });
    let phrase = buildPassphrase(chosen, opts.style);
    phrase = ensureDigitAndSpecial(phrase, opts.ensureDigit, opts.ensureSpecial);

    // Must be 12–32 and meet 3-of-4 groups; passphrases typically have upper+lower; we add digit+special by default
    const policyErrs = validatePolicy(phrase);
    if (policyErrs.length) continue;

    if (opts.blockBanned){
      const bad = containsBannedWord(phrase);
      if (bad) continue;
    }

    if (!isRepeat(phrase, scope, opts.noRepeat)){
      remember(phrase, scope, opts.noRepeat);
      return { value: phrase, wordlistSize: listToUse.length, sourceName };
    }
  }

  throw new Error("Could not find a compliant, unique passphrase. Add more words or change style/word count.");
}

// =====================
// Strength + crack time (estimates)
// =====================
function entropyPassword(len, poolSize){
  return len * Math.log2(poolSize);
}

function entropyPassphrase(wordCount, wordlistSize, ensureDigit, ensureSpecial){
  // Approximate: words * log2(wordlistSize) + digit/symbol if ensured.
  let bits = wordCount * Math.log2(Math.max(wordlistSize, 2));
  if (ensureDigit) bits += Math.log2(10);
  if (ensureSpecial) bits += Math.log2(SETS.symbols.length);
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

function pushWarning(msg){
  const li = document.createElement("li");
  li.textContent = msg;
  el("warnings").appendChild(li);
}

function regenerate(){
  try{
    el("warnings").innerHTML = "";
    el("copyStatus").textContent = "";

    const mode = val("mode") || "password";
    const piName = val("piName");
    const piBirth = val("piBirth");

    let outValue = "";
    let bits = 0;

    if (mode === "password"){
      const opts = {
        length: Number(val("length") || 16),
        lower: isChecked("lower"),
        upper: isChecked("upper"),
        digits: isChecked("digits"),
        symbols: isChecked("symbols"),
        allowSpaces: isChecked("allowSpaces"),
        noAmbiguous: isChecked("noAmbiguous"),
        exclude: val("exclude"),
        blockBanned: isChecked("blockBanned"),
        noRepeat: isChecked("noRepeatPwd")
      };

      // Force length inside 12–32 no matter what
      opts.length = Math.max(POLICY.minLen, Math.min(POLICY.maxLen, opts.length));

      const out = generatePasswordNoRepeat(opts);
      outValue = out.value;

      // Warnings / checks
      const bad = opts.blockBanned ? containsBannedWord(outValue) : null;
      if (bad) pushWarning(`Blocked not-allowed word: ${bad}`);

      const piHits = containsPersonalInfo(outValue, piName, piBirth);
      if (piHits.length) pushWarning(`Contains personal info: ${piHits.join(", ")} (change inputs/options).`);

      const policyErrs = validatePolicy(outValue);
      policyErrs.forEach(pushWarning);

      bits = entropyPassword(outValue.length, out.poolSize);

    } else {
      const opts = {
        customWords: val("customWords"),
        useCustomOnly: isChecked("useCustomOnly"),
        words: Number(val("words") || 4),
        style: val("phraseStyle") || "camel",
        allowRepeats: isChecked("allowRepeats"),
        ensureDigit: isChecked("ensureDigit"),
        ensureSpecial: isChecked("ensureSpecial"),
        blockBanned: isChecked("blockBannedPass"),
        noRepeat: isChecked("noRepeatPhrase")
      };

      const out = generatePassphraseNoRepeat(opts);
      outValue = out.value;

      pushWarning(`Passphrase source: ${out.sourceName} (${out.wordlistSize} words).`);

      const piHits = containsPersonalInfo(outValue, piName, piBirth);
      if (piHits.length) pushWarning(`Contains personal info: ${piHits.join(", ")} (edit your word list).`);

      const policyErrs = validatePolicy(outValue);
      policyErrs.forEach(pushWarning);

      const bad = opts.blockBanned ? containsBannedWord(outValue) : null;
      if (bad) pushWarning(`Contains not-allowed word: ${bad} (edit word list or disable).`);

      bits = entropyPassphrase(opts.words, out.wordlistSize, opts.ensureDigit, opts.ensureSpecial);
    }

    el("password").value = outValue;

    // Strength display
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

// password length slider
el("length").addEventListener("input", (e) => {
  el("lengthValue").textContent = e.target.value;
  regenerate();
});

// passphrase word count slider
el("words").addEventListener("input", (e) => {
  el("wordsValue").textContent = e.target.value;
  regenerate();
});

[
  "lower","upper","digits","symbols",
  "allowSpaces","noAmbiguous","exclude","blockBanned","noRepeatPwd",
  "customWords","useCustomOnly","allowRepeats","ensureDigit","ensureSpecial","blockBannedPass","noRepeatPhrase",
  "phraseStyle",
  "piName","piBirth"
].forEach(id => {
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
el("wordsValue").textContent = val("words") || "4";
setModeUI();
