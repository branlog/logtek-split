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
function verifyProxySignature(req) {
  try {
    const original = req.originalUrl || req.url || "";
    const pathOnly = original.split("?")[0] || "/prepare";
    const qs = original.includes("?") ? original.split("?")[1] : "";

    const params = new URLSearchParams(qs);
    const providedHmac = params.get("hmac");
    const providedSig  = params.get("signature");

    // ---> Nouveau : on prend l'un ou l'autre, même algo SHA256
    const provided = providedHmac || providedSig;
    if (!provided) return false;

    // Retirer les champs de signature avant de construire la chaîne
    params.delete("hmac");
    params.delete("signature");

    // Query triée (clé asc) + encodage standard
    const sorted = new URLSearchParams(
      Array.from(params.entries()).sort((a, b) => a[0].localeCompare(b[0]))
    ).toString();

    // On doit tester au moins ces bases :
    const expressPath = req.path || pathOnly;                 // ex: "/prepare"
    const proxyPath   = `/apps/logtek-split${expressPath}`;   // ex: "/apps/logtek-split/prepare"
    const proxyRoot   = `/apps/logtek-split`;                 // ex: "/apps/logtek-split"

    const candidates = [
      sorted ? `${expressPath}?${sorted}` : expressPath,
      sorted ? `${proxyPath}?${sorted}`   : proxyPath,
      sorted ? `${proxyRoot}?${sorted}`   : proxyRoot,
    ];

    for (const base of candidates) {
      const digest = crypto.createHmac("sha256", APP_PROXY_SECRET)
        .update(base)
        .digest("hex");

      const ok = crypto.timingSafeEqual(
        Buffer.from(digest, "utf8"),
        Buffer.from(provided, "utf8")
      );

      console.log(`[Proxy HMAC] base="${base}" | d8=${digest.slice(0,8)} | p8=${provided.slice(0,8)} | ok=${ok}`);
      if (ok) return true;
    }

    console.log("[Proxy] aucune variante ne matche → 401");
    return false;
  } catch (e) {
    console.log("[Proxy] exception verify:", e?.message || e);
    return false;
  }
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
