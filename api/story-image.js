export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      res.status(405).json({ error: "Method not allowed" });
      return;
    }

    const key = process.env.OPENAI_API_KEY;
    if (!key) {
      res.status(500).json({ error: "Server missing OPENAI_API_KEY" });
      return;
    }

    const { prompt } = req.body || {};
    if (!prompt || typeof prompt !== "string" || prompt.length < 5) {
      res.status(400).json({ error: "Missing/invalid prompt" });
      return;
    }

    // IMPORTANT: Do not send the full password by default.
    // Send only a "safe prompt" describing the scene.
    // Uses the OpenAI Images API (gpt-image-1).
    const resp = await fetch("https://api.openai.com/v1/images/generations", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-image-1",
        prompt,
        size: "512x512"
      })
    });

    if (!resp.ok) {
      const text = await resp.text();
      res.status(500).json({ error: "OpenAI error", detail: text });
      return;
    }

    const data = await resp.json();

    // The API can return different formats depending on settings.
    // Common: base64 image in data[0].b64_json
    const item = data?.data?.[0];

    if (item?.b64_json) {
      res.status(200).json({ b64: item.b64_json });
      return;
    }

    if (item?.url) {
      res.status(200).json({ url: item.url });
      return;
    }

    res.status(500).json({ error: "Unexpected image response format" });
  } catch (e) {
    res.status(500).json({ error: "Server error", detail: String(e?.message || e) });
  }
}
