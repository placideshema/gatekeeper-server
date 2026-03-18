// =============================================================================
//  GateKeeper Proxy Server — Production (Railway/Render/Fly.io)
// =============================================================================

require("dotenv").config();
const express   = require("express");
const helmet    = require("helmet");
const cors      = require("cors");
const rateLimit = require("express-rate-limit");

const app    = express();
const PORT   = process.env.PORT             || 3000;
const VT_KEY = process.env.VT_API_KEY;
const TOKEN  = process.env.PROXY_AUTH_TOKEN;

if (!VT_KEY)  { console.error("❌ VT_API_KEY missing");  process.exit(1); }
if (!TOKEN)   { console.error("❌ PROXY_AUTH_TOKEN missing"); process.exit(1); }

app.use(helmet());
app.use(express.json());

// ─── CORS — accept requests from Chrome extensions only ──────────────────────
app.use(cors({
  origin: (origin, callback) => {
    // Allow Chrome extensions and local dev
    if (!origin ||
        origin.startsWith("chrome-extension://") ||
        origin.startsWith("moz-extension://") ||
        origin === "http://localhost:3000") {
      return callback(null, true);
    }
    console.warn(`[GateKeeper] Blocked origin: ${origin}`);
    callback(new Error("Not allowed"));
  }
}));

// ─── Rate limiting ────────────────────────────────────────────────────────────
// Per-IP limit to protect your VT quota across all users
app.use("/scan", rateLimit({
  windowMs: 60 * 1000,
  max:      4,           // 4 scans/min per user (VT free tier)
  keyGenerator: (req) => req.headers["x-forwarded-for"] || req.ip,
  message: { error: "RATE_LIMIT" }
}));

// ─── Auth ─────────────────────────────────────────────────────────────────────
function requireToken(req, res, next) {
  if (req.headers["x-proxy-token"] !== TOKEN) {
    console.warn("[GateKeeper] Unauthorized request");
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function vtBase64(url) {
  return Buffer.from(url).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fmtStats(s) {
  return {
    status:     "scanned",
    malicious:  s.malicious  || 0,
    suspicious: s.suspicious || 0,
    harmless:   s.harmless   || 0,
    undetected: s.undetected || 0
  };
}

// =============================================================================
//  Routes
// =============================================================================

app.get("/", (_req, res) => res.json({
  name:    "GateKeeper Proxy",
  version: "4.0.0",
  status:  "running"
}));

app.get("/health", (_req, res) => res.json({
  status: "GateKeeper running",
  time:   new Date().toISOString()
}));

// ── Scan URL ──────────────────────────────────────────────────────────────────
app.post("/scan/url", requireToken, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing url" });

  try {
    const r = await fetch(
      `https://www.virustotal.com/api/v3/urls/${vtBase64(url)}`,
      { headers: { "x-apikey": VT_KEY } }
    );

    if (r.status === 404) {
      // Submit unknown URL to VT
      fetch("https://www.virustotal.com/api/v3/urls", {
        method:  "POST",
        headers: { "x-apikey": VT_KEY, "Content-Type": "application/x-www-form-urlencoded" },
        body:    `url=${encodeURIComponent(url)}`
      }).catch(() => {});
      return res.json({ status: "unknown" });
    }
    if (r.status === 429) return res.status(429).json({ error: "RATE_LIMIT" });
    if (!r.ok)            return res.status(502).json({ error: "VT_ERROR" });

    const j = await r.json();
    console.log(`[GateKeeper] URL: ${url.slice(0,60)} → malicious:${j.data.attributes.last_analysis_stats.malicious}`);
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
    const r = await fetch(
      `https://www.virustotal.com/api/v3/files/${hash}`,
      { headers: { "x-apikey": VT_KEY } }
    );

    if (r.status === 404) return res.json({ status: "unknown" });
    if (r.status === 429) return res.status(429).json({ error: "RATE_LIMIT" });
    if (!r.ok)            return res.status(502).json({ error: "VT_ERROR" });

    const j = await r.json();
    console.log(`[GateKeeper] Hash: ${hash.slice(0,20)} → malicious:${j.data.attributes.last_analysis_stats.malicious}`);
    return res.json(fmtStats(j.data.attributes.last_analysis_stats));

  } catch (e) {
    console.error("[GateKeeper] Hash error:", e.message);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ GateKeeper Proxy running on port ${PORT}`);
});
