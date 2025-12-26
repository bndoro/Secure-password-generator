// =====================
// POLICY
// =====================
const POLICY = {
  minLen: 12,
  maxLen: 32,
  // Must contain at least 3 of these 4 groups:
  // uppercase, lowercase, digits, specials (spaces allowed separately)
  specials: "~`!#$%*()_+-={}[]:';?,./"
};

// Banned/common words (starter list; expand later)
const BANNED_WORDS = [
  "password", "qwerty", "letmein", "admin", "welcome", "iloveyou", "rowdy"
];

// =====================
// SETS
// =====================
const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: POLICY.specials,
  space: " "
};

const AMBIGUOUS = new Set(["O", "0", "I", "1", "l"]);

// Uncommon fallback words (for passphrase + story)
const WORDS = {
  adjectives: ["grumpy","silent","curious","rapid","gentle","odd","tiny","brave","sleepy","wild","electric","cosmic","frozen","noisy","saffron"],
  nouns: ["toaster","falcon","lantern","robot","turtle","cloud","ticket","vault","planet","river","anchor","kernel","socket","prism","matrix","packet"],
  verbsPast: ["bit","guarded","fixed","chased","moved","tested","saved","lost","found","touched","patched","blocked","scanned","logged"],
  objects: ["cloud","vault","firewall","cookie","signal","packet","planet","puzzle","notebook","router","server","badge","portal","ledger"]
};

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
// Random helpers (CSPRNG for passwords)
// =====================
function randomInt(maxExclusive){
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % maxExclusive;
}
function pick(list){
  return list[randomInt(list.length)];
}
function pickChar(str){
  return str[randomInt(str.length)];
}
function shuffle(arr){
  for (let i = arr.length - 1; i > 0; i--){
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// =====================
// No-repeat tracking (hashed history)
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
function makeHistoryKey(scope){ return `pwgen_history_${scope}`; }
function loadHistory(scope){
  try{
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
  return loadHistory(scope).has(hash);
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
// Banned words + personal info checks
// =====================
function containsBannedWord(s){
  const x = (s || "").toLowerCase();
  for (const w of BANNED_WORDS){
    if (w && x.includes(w)) return w;
  }
  return null;
}
function containsPersonalInfo(s, name, birth){
  const x = (s || "").toLowerCase();
  const hits = [];
  const n = (name || "").trim().toLowerCase();
  const b = (birth || "").trim().toLowerCase();

  if (n && n.length >= 3 && x.includes(n)) hits.push(`name/username (“${name}”)`);
  if (b && b.length >= 2 && x.includes(b)) hits.push(`birth info (“${birth}”)`);
  return hits;
}

// =====================
// Policy validation (12–32, 3-of-4 groups, space rule)
// =====================
function escapeForCharClass(chars){
  return chars.replace(/[-\\\]^\n]/g, "\\$&");
}
function countGroupsPresent(s){
  const hasUpper = /[A-Z]/.test(s);
  const hasLower = /[a-z]/.test(s);
  const hasDigit = /[0-9]/.test(s);
  const hasSymbol = new RegExp("[" + escapeForCharClass(POLICY.specials) + "]").test(s);
  const present = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
  return { present, hasUpper, hasLower, hasDigit, hasSymbol };
}
function validatePolicy(s){
  const errs = [];
  if (s.length < POLICY.minLen) errs.push(`Too short (min ${POLICY.minLen}).`);
  if (s.length > POLICY.maxLen) errs.push(`Too long (max ${POLICY.maxLen}).`);
  if (s.startsWith(" ") || s.endsWith(" ")) errs.push("Spaces not allowed at beginning or end.");
  const g = countGroupsPresent(s);
  if (g.present < 3) errs.push("Needs at least 3 of 4 groups: upper, lower, digits, special.");
  return errs;
}

// =====================
// Strength label (simple)
 // =====================
function strengthLabel(s){
  const g = countGroupsPresent(s).present;
  if (s.length >= 20 && g >= 3) return { label: "Very Strong", pct: 90 };
  if (s.length >= 16 && g >= 3) return { label: "Strong", pct: 75 };
  if (s.length >= 12 && g >= 3) return { label: "Fair", pct: 55 };
  return { label: "Weak", pct: 25 };
}

// =====================
// Password (random) generator enforcing 3-of-4 selection
// =====================
function buildPasswordPool(opts){
  const exclude = new Set((opts.exclude || "").split(""));
  const groups = [];
  let pool = "";

  const keep = (c) => {
    if (exclude.has(c)) return false;
    if (opts.noAmbiguous && AMBIGUOUS.has(c)) return false;
    if (c === " " && !opts.allowSpaces) return false;
    return true;
  };

  const selected = ["upper","lower","digits","symbols"].filter(k => opts[k]);
  if (selected.length < 3){
    throw new Error("Policy requires at least 3 of 4 groups. Select at least three: upper, lower, digits, special.");
  }

  for (const key of ["lower","upper","digits","symbols"]){
    if (!opts[key]) continue;
    const g = SETS[key].split("").filter(keep).join("");
    if (g.length === 0) continue;
    groups.push(g);
    pool += g;
  }

  if (opts.allowSpaces && keep(" ")){
    pool += " ";
  }

  if (!pool || groups.length === 0) throw new Error("No valid characters available. Adjust options/exclusions.");
  if (opts.length < groups.length) throw new Error("Length too short for selected groups.");

  return { pool, groups };
}

function fixEdgeSpaces(arr){
  if (arr[0] !== " " && arr[arr.length - 1] !== " ") return arr;

  for (let i = 1; i < arr.length - 1; i++){
    if (arr[i] !== " "){
      if (arr[0] === " ") [arr[0], arr[i]] = [arr[i], arr[0]];
      if (arr[arr.length - 1] === " ") [arr[arr.length - 1], arr[i]] = [arr[i], arr[arr.length - 1]];
      break;
    }
  }
  if (arr[0] === " ") arr[0] = pickChar(SETS.symbols);
  if (arr[arr.length - 1] === " ") arr[arr.length - 1] = pickChar(SETS.symbols);
  return arr;
}

function generatePasswordOnce(opts){
  const { pool, groups } = buildPasswordPool(opts);
  const out = [];

  for (const g of groups) out.push(g[randomInt(g.length)]);
  while (out.length < opts.length) out.push(pool[randomInt(pool.length)]);

  shuffle(out);
  fixEdgeSpaces(out);

  return out.join("");
}

function generatePasswordNoRepeat(opts){
  const scope = `pwd_${fnv1a32(JSON.stringify(opts))}`;
  const MAX_TRIES = 400;

  for (let i = 0; i < MAX_TRIES; i++){
    const s = generatePasswordOnce(opts);

    if (opts.blockBanned){
      const bad = containsBannedWord(s);
      if (bad) continue;
    }

    if (validatePolicy(s).length) continue;

    if (!isRepeat(s, scope, opts.noRepeat)){
      remember(s, scope, opts.noRepeat);
      return s;
    }
  }
  throw new Error("Could not find a compliant, unique password. Try different settings.");
}

// =====================
// Passphrase generator (Option A style)
// =====================
function parseWords(text){
  return (text || "")
    .split(/[\n,]+/g)
    .map(w => w.trim())
    .filter(Boolean);
}

function titleCase(w){
  if (!w) return w;
  return w[0].toUpperCase() + w.slice(1).toLowerCase();
}

function pickWordsFromList(list, count, allowRepeats){
  if (!allowRepeats && count > list.length) {
    throw new Error("Not enough unique words. Enable word reuse or add more words.");
  }

  const chosen = [];
  const available = [...list];

  for (let i = 0; i < count; i++){
    const src = allowRepeats ? list : available;
    const w = pick(src);
    chosen.push(w);
    if (!allowRepeats){
      const idx = available.indexOf(w);
      if (idx >= 0) available.splice(idx, 1);
    }
  }
  return chosen;
}

function joinPassphrase(wordsTitle, style, separator){
  if (style === "camel") return wordsTitle.join("");
  if (style === "underscore"){
    if (wordsTitle.length <= 1) return wordsTitle.join("");
    return wordsTitle.slice(0, -1).join("") + "_" + wordsTitle[wordsTitle.length - 1];
  }
  if (style === "spaced"){
    return wordsTitle.join(" ");
  }
  // custom separator
  const sep = (separator ?? "").toString(); // can be blank to remove "-"
  return wordsTitle.join(sep);
}

function twoDigits(){
  // 10–99
  return String(randomInt(90) + 10);
}

function generatePassphraseNoRepeat(opts){
  // choose list: custom or built-in
  let list = parseWords(opts.customWords);
  let sourceName = "custom";
  if (list.length === 0){
    list = DEFAULT_WORDLIST;
    sourceName = "built-in";
  }

  // normalize title case
  const scope = `phrase_${fnv1a32(JSON.stringify({
    words: opts.words,
    style: opts.style,
    separator: opts.separator,
    ensureDigit: opts.ensureDigit,
    ensureSpecial: opts.ensureSpecial,
    allowRepeats: opts.allowRepeats,
    blockBanned: opts.blockBanned,
    listHash: fnv1a32(list.map(w => w.toLowerCase()).sort().join(","))
  }))}`;

  const MAX_TRIES = 400;

  for (let i = 0; i < MAX_TRIES; i++){
    const chosenRaw = pickWordsFromList(list, opts.words, opts.allowRepeats);
    const chosen = chosenRaw.map(titleCase);

    let phrase = joinPassphrase(chosen, opts.style, opts.separator);

    if (opts.ensureDigit) phrase += twoDigits();
    if (opts.ensureSpecial) phrase += pickChar(SETS.symbols);

    phrase = phrase.trim();
    if (phrase.length < POLICY.minLen){
      while (phrase.length < POLICY.minLen) phrase += pickChar(SETS.digits);
    }
    if (phrase.length > POLICY.maxLen){
      // try removing spaces first, then trim
      phrase = phrase.replace(/\s+/g, "");
      if (phrase.length > POLICY.maxLen) phrase = phrase.slice(0, POLICY.maxLen);
    }

    if (opts.blockBanned){
      const bad = containsBannedWord(phrase);
      if (bad) continue;
    }

    if (validatePolicy(phrase).length) continue;

    if (!isRepeat(phrase, scope, opts.noRepeat)){
      remember(phrase, scope, opts.noRepeat);
      return { value: phrase, sourceName, listSize: list.length };
    }
  }

  throw new Error("Could not find a compliant, unique passphrase. Add more words or change style/word count.");
}

// =====================
// Story-Mode generator (structured grammar rules)
// =====================
function title(w){ return titleCase(w); }

function generateStoryOnce(templateId){
  const adj = title(pick(WORDS.adjectives));
  const noun = title(pick(WORDS.nouns));
  const verb = title(pick(WORDS.verbsPast));
  const obj  = title(pick(WORDS.objects));

  if (templateId === "t1") return `The${adj}${noun}${verb}My${obj}`;
  if (templateId === "t2") return `A${adj}${noun}${verb}The${obj}`;
  return `This${noun}${verb}That${obj}`; // t3
}

function generateStoryNoRepeat(opts){
  const scope = `story_${fnv1a32(JSON.stringify(opts))}`;
  const MAX_TRIES = 500;

  for (let i = 0; i < MAX_TRIES; i++){
    let s = generateStoryOnce(opts.template);

    if (opts.addDigits) s += twoDigits();
    if (opts.addSpecial) s += pickChar(SETS.symbols);

    // enforce length bounds
    if (s.length < POLICY.minLen){
      while (s.length < POLICY.minLen) s += pickChar(SETS.digits);
    }
    if (s.length > POLICY.maxLen){
      s = s.slice(0, POLICY.maxLen);
    }

    if (opts.blockBanned){
      const bad = containsBannedWord(s);
      if (bad) continue;
    }

    if (validatePolicy(s).length) continue;

    if (!isRepeat(s, scope, opts.noRepeat)){
      remember(s, scope, opts.noRepeat);
      return s;
    }
  }

  throw new Error("Could not find a compliant, unique story password. Try changing template/options.");
}

// =====================
// Phone-mode readout
// =====================
const SYMBOL_READOUT = {
  "!": "exclamation",
  "@": "at",
  "#": "hashtag",
  "$": "dollar",
  "%": "percent",
  "*": "asterisk",
  "~": "tilde",
  "`": "backtick",
  "(": "open parenthesis",
  ")": "close parenthesis",
  "_": "underscore",
  "+": "plus",
  "-": "dash",
  "=": "equals",
  "{": "open brace",
  "}": "close brace",
  "[": "open bracket",
  "]": "close bracket",
  ":": "colon",
  "'": "apostrophe",
  ";": "semicolon",
  "?": "question mark",
  ",": "comma",
  ".": "dot",
  "/": "slash"
};

function splitCamelCaseWords(s){
  // Split CamelCase into tokens; keep digits and symbols separate
  // Example: TheGrumpyToasterBitMyCloud21! -> ["The","Grumpy","Toaster","Bit","My","Cloud","2","1","!"]
  const tokens = [];
  let buf = "";

  const flush = () => { if (buf) { tokens.push(buf); buf = ""; } };

  for (let i = 0; i < s.length; i++){
    const c = s[i];

    const isUpper = c >= "A" && c <= "Z";
    const isLower = c >= "a" && c <= "z";
    const isDigit = c >= "0" && c <= "9";
    const isSpace = c === " ";

    const isSymbol = !isUpper && !isLower && !isDigit && !isSpace;

    if (isSpace){
      flush();
      continue;
    }

    if (isDigit || isSymbol){
      flush();
      tokens.push(c);
      continue;
    }

    // letter
    if (isUpper && buf && (buf[buf.length - 1] >= "a" && buf[buf.length - 1] <= "z")){
      // boundary: ...aB...
      flush();
      buf = c;
    } else {
      buf += c;
    }
  }
  flush();
  return tokens;
}

function phoneReadout(password){
  const tokens = splitCamelCaseWords(password);
  const out = tokens.map(t => {
    if (t.length === 1 && t >= "0" && t <= "9") return t; // digit spoken as itself
    if (t.length === 1 && SYMBOL_READOUT[t]) return SYMBOL_READOUT[t];
    if (t.length === 1 && !(t >= "0" && t <= "9")) return `symbol ${t}`;
    return t;
  });

  // Make digits read spaced: "2 1" instead of "21"
  return out.join(" ");
}

// =====================
// UI helpers
// =====================
function clearLists(){
  el("warnings").innerHTML = "";
  el("policyChecklist").innerHTML = "";
}

function addChecklistItem(ok, text){
  const li = document.createElement("li");
  li.textContent = (ok ? "✅ " : "❌ ") + text;
  el("policyChecklist").appendChild(li);
}

function addNote(text){
  const li = document.createElement("li");
  li.textContent = text;
  el("warnings").appendChild(li);
}

function renderChecklistAndNotes(password, name, birth, blockBanned){
  const errs = validatePolicy(password);
  const g = countGroupsPresent(password);

  addChecklistItem(password.length >= POLICY.minLen, `Minimum length (${POLICY.minLen})`);
  addChecklistItem(password.length <= POLICY.maxLen, `Maximum length (${POLICY.maxLen})`);
  addChecklistItem(!(password.startsWith(" ") || password.endsWith(" ")), "No leading/trailing spaces");
  addChecklistItem(g.present >= 3, "At least 3 of 4 groups (upper/lower/digits/special)");

  if (errs.length){
    errs.forEach(e => addNote(`Policy: ${e}`));
  }

  if (blockBanned){
    const bad = containsBannedWord(password);
    if (bad) addNote(`Contains banned/common word: ${bad}`);
  }

  const piHits = containsPersonalInfo(password, name, birth);
  if (piHits.length){
    addNote(`Warning: contains personal info (${piHits.join(", ")}).`);
  }
}

function setModeUI(){
  const mode = val("mode") || "password";
  el("passwordControls").style.display = mode === "password" ? "" : "none";
  el("passphraseControls").style.display = mode === "passphrase" ? "" : "none";
  el("storyControls").style.display = mode === "story" ? "" : "none";
  regenerate();
}

// =====================
// Main generator
// =====================
function regenerate(){
  try{
    clearLists();
    el("copyStatus").textContent = "";

    const mode = val("mode") || "password";
    const name = val("piName");
    const birth = val("piBirth");

    let password = "";
    let blockBanned = true;

    if (mode === "password"){
      const opts = {
        length: Math.max(POLICY.minLen, Math.min(POLICY.maxLen, Number(val("length") || 16))),
        lower: isChecked("lower"),
        upper: isChecked("upper"),
        digits: isChecked("digits"),
        symbols: isChecked("symbols"),
        allowSpaces: isChecked("allowSpaces"),
        noAmbiguous: isChecked("noAmbiguous"),
        exclude: val("exclude"),
        blockBanned: isChecked("blockBannedPwd"),
        noRepeat: isChecked("noRepeatPwd")
      };
      blockBanned = opts.blockBanned;
      password = generatePasswordNoRepeat(opts);
    }

    if (mode === "passphrase"){
      const opts = {
        customWords: val("customWords"),
        words: Number(val("words") || 4),
        style: val("phraseStyle") || "camel",
        separator: val("separator") || "", // blank removes "-"
        ensureDigit: isChecked("ensureDigit"),
        ensureSpecial: isChecked("ensureSpecial"),
        allowRepeats: isChecked("allowWordRepeats"),
        blockBanned: isChecked("blockBannedPhrase"),
        noRepeat: isChecked("noRepeatPhrase")
      };
      blockBanned = opts.blockBanned;
      const out = generatePassphraseNoRepeat(opts);
      password = out.value;
      addNote(`Passphrase source: ${out.sourceName} (${out.listSize} words).`);
    }

    if (mode === "story"){
      const opts = {
        template: val("storyTemplate") || "t1",
        addDigits: isChecked("storyDigits"),
        addSpecial: isChecked("storySpecial"),
        noRepeat: isChecked("storyNoRepeat"),
        blockBanned: isChecked("blockBannedStory")
      };
      blockBanned = opts.blockBanned;
      password = generateStoryNoRepeat(opts);
    }

    el("password").value = password;

    // Strength bar
    const s = strengthLabel(password);
    el("strengthLabel").textContent = s.label;
    el("barFill").style.width = s.pct + "%";

    // Checklist + notes
    renderChecklistAndNotes(password, name, birth, blockBanned);

    // Phone readout
    const showReadout = (mode === "story") ? isChecked("phoneMode") : true;
    el("readoutPanel").style.display = showReadout ? "" : "none";
    if (showReadout){
      el("readoutText").textContent = phoneReadout(password);
    } else {
      el("readoutText").textContent = "";
    }

  } catch (err){
    clearLists();
    el("password").value = "";
    el("strengthLabel").textContent = "—";
    el("barFill").style.width = "0%";
    addNote(err.message);
    el("readoutText").textContent = "";
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

el("words").addEventListener("input", (e) => {
  el("wordsValue").textContent = e.target.value;
  regenerate();
});

[
  "lower","upper","digits","symbols","allowSpaces","noAmbiguous","exclude","blockBannedPwd","noRepeatPwd",
  "customWords","phraseStyle","separator","ensureDigit","ensureSpecial","allowWordRepeats","blockBannedPhrase","noRepeatPhrase",
  "storyTemplate","storyDigits","storySpecial","storyNoRepeat","blockBannedStory","phoneMode",
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
