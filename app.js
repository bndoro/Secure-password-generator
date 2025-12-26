// =====================
// Word lists
// =====================
const UNCOMMON_WORDS = [
  "lantern","cipher","vertex","cobalt","ember","quartz","falcon","matrix",
  "aurora","nimbus","kernel","anchor","prism","socket","carbon","zenith"
];

const DIGITS = "0123456789";
const SYMBOLS = "!@#$%*";

// =====================
// Helpers
// =====================
function el(id){ return document.getElementById(id); }
function rand(arr){ return arr[Math.floor(Math.random() * arr.length)]; }
function randChar(str){ return str[Math.floor(Math.random() * str.length)]; }

// =====================
// One-Word Password Generator
// =====================
function generateOneWordPassword(){
  const source = el("oneWordSource").value;
  let words = UNCOMMON_WORDS;

  if (source === "custom"){
    const custom = el("oneWordCustom").value
      .split(/[\n,]+/)
      .map(w => w.trim())
      .filter(Boolean);
    if (custom.length > 0) words = custom;
  }

  let word = rand(words);

  if (el("oneWordCap").checked){
    word = word[0].toUpperCase() + word.slice(1);
  }

  let result = word;

  if (el("oneWordDigit").checked){
    result += randChar(DIGITS) + randChar(DIGITS);
  }

  if (el("oneWordSymbol").checked){
    result += randChar(SYMBOLS);
  }

  // Ensure length >= 12
  while (result.length < 12){
    result += randChar(DIGITS);
  }

  return result;
}

// =====================
// Passphrase Generator
// =====================
function generatePassphrase(){
  let words = el("customWords").value
    .split(/[\n,]+/)
    .map(w => w.trim())
    .filter(Boolean);

  if (words.length === 0){
    words = UNCOMMON_WORDS;
  }

  const count = Number(el("words").value);
  const sep = el("separator").value || "";

  let chosen = [];
  for (let i = 0; i < count; i++){
    const w = rand(words);
    chosen.push(w[0].toUpperCase() + w.slice(1));
  }

  let phrase = chosen.join(sep);

  if (el("ensureDigit").checked && !/[0-9]/.test(phrase)){
    phrase += randChar(DIGITS);
  }

  if (el("ensureSpecial").checked && !/[!@#$%*]/.test(phrase)){
    phrase += randChar(SYMBOLS);
  }

  return phrase;
}

// =====================
// UI Logic
// =====================
function setMode(){
  const mode = el("mode").value;
  el("passwordControls").style.display = mode === "password" ? "" : "none";
  el("oneWordControls").style.display = mode === "oneword" ? "" : "none";
  el("passphraseControls").style.display = mode === "passphrase" ? "" : "none";
  regenerate();
}

function regenerate(){
  const mode = el("mode").value;
  let value = "";

  if (mode === "oneword"){
    value = generateOneWordPassword();
  } else if (mode === "passphrase"){
    value = generatePassphrase();
  } else {
    value = "RandomPassword#123"; // placeholder for existing random logic
  }

  el("password").value = value;
  el("strengthLabel").textContent = value.length >= 16 ? "Strong" : "Fair";
  el("barFill").style.width = value.length >= 16 ? "75%" : "50%";
}

// =====================
// Events
// =====================
el("mode").addEventListener("change", setMode);
el("regen").addEventListener("click", regenerate);

el("toggle").addEventListener("click", () => {
  const pw = el("password");
  pw.type = pw.type === "password" ? "text" : "password";
});

el("copy").addEventListener("click", () => {
  navigator.clipboard.writeText(el("password").value);
});

// Init
el("lengthValue").textContent = el("length")?.value || "16";
setMode();
