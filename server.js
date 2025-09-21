import express from "express";
import jwt from "jsonwebtoken";
import path from "path";
import fetch from "node-fetch";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// === Environment variables ===
const SECRET = process.env.REDIRECT_SECRET || "unsafe-dev-secret";
const ALLOWED_REFS = (process.env.ALLOWED_REF || "").split(",").map(r => r.trim()).filter(Boolean);
const REDIRECT_URL = process.env.REDIRECT_URL || "https://example.com";
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN || null;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || null;

// === Helper: send logs to Telegram ===
async function sendToTelegram(message) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  const url = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: message }),
    });
  } catch (err) {
    console.error("Telegram error:", err?.message || err);
  }
}

// === Middleware: Bot/referrer checks ===
app.use((req, res, next) => {
  const ref = req.get("referer") || req.get("origin") || "";
  const ua = req.get("user-agent") || "";
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();

  let status = "✅ Allowed";

  // Only block if ref is present AND not in allowed list
  if (ALLOWED_REFS.length > 0 && ref && !ALLOWED_REFS.some(domain => ref.startsWith(domain))) {
    status = "❌ Blocked (bad referrer)";
    sendToTelegram(`${status}\nIP: ${ip}\nUA: ${ua}\nRef: ${ref || 'none'}`);
    return res.status(403).send("Forbidden: bad referrer");
  }

  // Block obvious bots
  if (/\b(bot|crawl|spider|scanner|wget|curl|python-requests)\b/i.test(ua)) {
    status = "❌ Blocked (bot UA)";
    sendToTelegram(`${status}\nIP: ${ip}\nUA: ${ua}\nRef: ${ref || 'none'}`);
    return res.status(403).send("Forbidden: bot detected (UA)");
  }

  sendToTelegram(`${status}\nIP: ${ip}\nUA: ${ua}\nRef: ${ref || 'none'}`);
  next();
});

// === Root redirect to secure page ===
app.get("/", (req, res) => {
  res.redirect("/secure-redirect");
});

// === Serve redirect page with embedded token ===
app.get("/secure-redirect", (req, res) => {
  try {
    const token = jwt.sign({ target: REDIRECT_URL }, SECRET, { expiresIn: "30s" });
    let html = fs.readFileSync(path.join(__dirname, "views", "redirect.html"), "utf8");
    html = html.replace("%%TOKEN%%", token); // inject token
    res.send(html);
  } catch (err) {
    console.error("Error signing token", err);
    res.status(500).send("Server error");
  }
});

// === Verify token and redirect ===
app.get("/verify", (req, res) => {
  const token = req.query.token;
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();

  if (!token) {
    sendToTelegram(`❌ Blocked (missing token)\nIP: ${ip}`);
    return res.status(400).send("Missing token");
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    return res.redirect(decoded.target);
  } catch (err) {
    sendToTelegram(`❌ Blocked (invalid token)\nIP: ${ip}`);
    return res.status(401).send("Unauthorized: invalid or expired token");
  }
});

// === Healthcheck endpoint ===
app.get("/healthz", (req, res) => res.send("ok"));

app.listen(PORT, () => console.log(`🚀 Secure-redirect listening on ${PORT}`));
