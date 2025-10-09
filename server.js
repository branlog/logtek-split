// server.js — Logtek Split Proxy — Render + Shopify App Proxy stable

import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET;
const PORT = process.env.PORT || 10000;

// --- Vérification HMAC proxy Shopify ---
function verifyProxyHmac(req) {
  const url = new URL(req.originalUrl, `https://${req.get("host")}`);
  const query = new URLSearchParams(url.searchParams);
  const hmac = query.get("hmac");

  if (!hmac) return false;
  query.delete("hmac");

  // Recrée le format que Shopify signe : path + ? + query trié
  const sortedParams = new URLSearchParams(
    Array.from(query.entries()).sort((a, b) => a[0].localeCompare(b[0]))
  );

  const message = `${req.path}?${sortedParams.toString()}`;
  const digest = crypto
    .createHmac("sha256", APP_PROXY_SECRET)
    .update(message)
    .digest("hex");

  const ok = crypto.timingSafeEqual(
    Buffer.from(digest, "utf8"),
    Buffer.from(hmac, "utf8")
  );

  console.log(
    `[Proxy HMAC] message="${message}" | digest8=${digest.slice(
      0,
      8
    )} | prov8=${hmac.slice(0, 8)} | ok=${ok}`
  );

  return ok;
}

// --- Route test /prepare ---
app.get("/prepare", async (req, res) => {
  if (!verifyProxyHmac(req)) {
    return res.status(403).json({ error: "Invalid proxy signature" });
  }

  // Ici, ça fonctionne -> renvoie un JSON de test
  res.json({ error: "Panier vide" });
});

// --- Health check ---
app.get("/health", (req, res) => res.json({ ok: true }));

// --- Démarrage serveur ---
app.listen(PORT, () => {
  console.log(`✅ Logtek Split en ligne sur port ${PORT}`);
});
