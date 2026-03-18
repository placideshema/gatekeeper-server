// =============================================================================
//  GateKeeper Proxy Server — server.js
//  Start with: node server.js
// =============================================================================

require("dotenv").config({ path: __dirname + "/.env" });

const express   = require("express");
const helmet    = require("helmet");
const cors      = require("cors");
const rateLimit = require("express-rate-limit");

const app    = express();
const PORT   = process.env.PORT             || 3000;
const VT_KEY = process.env.VT_API_KEY;
const TOKEN  = process.env.PROXY_AUTH_TOKEN || "GATEKEEPER_TOKEN";

if (!VT_KEY) {
  console.error("❌  VT_API_KEY missing from server/.env — add it and restart.");
  process.exit(1);
}

app.use(helmet());
app.use(express.json());
app.use(cors({ origin: "*" }));   // extension makes local requests only

// Rate limit to match VT free tier
app.use("/scan", rateLimit({ windowMs: 60000, max: 4, message: { error: "RATE_LIMIT" } }));

// Auth — every /scan call must carry the token
function requireToken(req, res, next) {
  if (req.headers["x-proxy-token"] !== TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// VT base64 encoding
function vtBase64(url) {
  return Buffer.from(url).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fmtStats(s) {
  return { status: "scanned", malicious: s.malicious||0, suspicious: s.suspicious||0,
           harmless: s.harmless||0, undetected: s.undetected||0 };
}

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health", (_req, res) =>
  res.json({ status: "GateKeeper running", port: PORT, time: new Date().toISOString() })
);

// ── Scan URL ──────────────────────────────────────────────────────────────────
app.post("/scan/url", requireToken, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing url" });

  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${vtBase64(url)}`,
      { headers: { "x-apikey": VT_KEY } });

    if (r.status === 404) {
      // Submit unknown URL for future analysis
      fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { "x-apikey": VT_KEY, "Content-Type": "application/x-www-form-urlencoded" },
        body: `url=${encodeURIComponent(url)}`
      }).catch(() => {});
      return res.json({ status: "unknown" });
    }
    if (r.status === 429) return res.status(429).json({ error: "RATE_LIMIT" });
    if (!r.ok)            return res.status(502).json({ error: "VT_ERROR" });

    const j = await r.json();
    console.log(`[GateKeeper] URL scan: ${url.slice(0,60)}… → malicious:${j.data.attributes.last_analysis_stats.malicious}`);
    return res.json(fmtStats(j.data.attributes.last_analysis_stats));

  } catch (e) {
    console.error("[GateKeeper] URL error:", e.message);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ── Scan Hash ─────────────────────────────────────────────────────────────────
app.post("/scan/hash", requireToken, async (req, res) => {
  const { hash } = req.body;
  if (!hash || !/^[a-f0-9]{64}$/i.test(hash))
    return res.status(400).json({ error: "Invalid SHA-256 hash" });

  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`,
      { headers: { "x-apikey": VT_KEY } });

    if (r.status === 404) return res.json({ status: "unknown" });
    if (r.status === 429) return res.status(429).json({ error: "RATE_LIMIT" });
    if (!r.ok)            return res.status(502).json({ error: "VT_ERROR" });

    const j = await r.json();
    console.log(`[GateKeeper] Hash scan: ${hash.slice(0,20)}… → malicious:${j.data.attributes.last_analysis_stats.malicious}`);
    return res.json(fmtStats(j.data.attributes.last_analysis_stats));

  } catch (e) {
    console.error("[GateKeeper] Hash error:", e.message);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║        GateKeeper Proxy Server       ║
╠══════════════════════════════════════╣
║  Status : ✅ Running                  ║
║  Port   : ${PORT}                          ║
║  API Key: [protected in .env]        ║
╚══════════════════════════════════════╝
  `);
});
