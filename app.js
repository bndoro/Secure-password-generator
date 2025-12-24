const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?"
};

const AMBIGUOUS = new Set(["O", "0", "I", "1", "l"]);

function el(id) {
  return document.getElementById(id);
}

function isChecked(id) {
  const element = el(id);
  return element ? element.checked : false;
}

function randomInt(max) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % max;
}

function generatePassword(length, opts) {
  let pool = "";
  let required = [];

  for (const key in SETS) {
    if (opts[key]) {
      let chars = SETS[key].split("").filter(c =>
        !opts.noAmbiguous || !AMBIGUOUS.has(c)
      );

      if (chars.length === 0) continue;

      pool += chars.join("");
      required.push(chars[randomInt(chars.length)]);
    }
  }

  if (!pool) return "";

  let result = [...required];
  while (result.length < length) {
    result.push(pool[randomInt(pool.length)]);
  }

  // Fisher-Yates shuffle
  for (let i = result.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result.join("");
}

function entropyBits(password, poolSize) {
  return password.length * Math.log2(poolSize);
}

function crackTime(bits, rate) {
  return (Math.pow(2, bits) / 2) / rate;
}

function formatTime(seconds) {
  if (!isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} sec`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hr`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

function regenerate() {
  try {
    const opts = {
      lower: isChecked("lower"),
      upper: isChecked("upper"),
      digits: isChecked("digits"),
      symbols: isChecked("symbols"),
      noAmbiguous: isChecked("noAmbiguous")
    };

    const length = Number(el("length").value);
    const password = generatePassword(length, opts);

    el("password").value = password;

    let poolSize = 0;
    for (const key in SETS) {
      if (opts[key]) poolSize += SETS[key].length;
    }

    const bits = entropyBits(password, poolSize);

    el("entropyBits").textContent = bits.toFixed(1);
    el("crackFast").textContent = formatTime(crackTime(bits, 1e10));
    el("crackOnline").textContent = formatTime(crackTime(bits, 10));

    let strength = "Weak";
    let pct = 20;
    if (bits > 70) { strength = "Very Strong"; pct = 90; }
    else if (bits > 50) { strength = "Strong"; pct = 70; }
    else if (bits > 35) { strength = "Fair"; pct = 45; }

    el("strengthLabel").textContent = strength;
    el("barFill").style.width = pct + "%";

    el("warnings").innerHTML = "";

  } catch (err) {
    el("warnings").innerHTML = `<li>${err.message}</li>`;
  }
}

el("length").addEventListener("input", e => {
  el("lengthValue").textContent = e.target.value;
  regenerate();
});

["lower","upper","digits","symbols","noAmbiguous"].forEach(id => {
  const checkbox = el(id);
  if (checkbox) checkbox.addEventListener("change", regenerate);
});

el("regen").addEventListener("click", regenerate);

el("toggle").addEventListener("click", () => {
  const pw = el("password");
  pw.type = pw.type === "password" ? "text" : "password";
});

el("copy").addEventListener("click", () => {
  navigator.clipboard.writeText(el("password").value);
  el("copyStatus").textContent = "Copied!";
  setTimeout(() => el("copyStatus").textContent = "", 1200);
});

regenerate();
