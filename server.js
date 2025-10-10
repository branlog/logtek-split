// server.js — Logtek Split (Express + Shopify App Proxy) — Node 18+ / Render
// ------------------------------------------------------

import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

// --- Config ---
const PORT = Number(process.env.PORT || 10000);
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET || "";
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN || "";
const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN || ""; // ex: 2uvcbu-ci.myshopify.com

if (!APP_PROXY_SECRET) console.warn("[BOOT] APP_PROXY_SECRET manquant");
if (!PORT) console.warn("[BOOT] PORT manquant, défaut 10000");

// --- App ---
const app = express();
app.disable("x-powered-by");

// Simple logger (sans bruit)
app.use((req, _res, next) => {
  if (req.path !== "/health") {
    console.log(`[REQ] ${req.method} ${req.originalUrl}`);
  }
  next();
});

// ----- Utils -----

function safeEq(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch {
    return false;
  }
}

/**
 * Vérifie la signature d'un App Proxy Shopify.
 * - Accepte le format "query triée" (ancien)
 * - Accepte le format "path(proxy)?query" (nouveau, avec path_prefix)
 * - Encodage strict via encodeURIComponent
 */
function verifyProxySignature(req) {
  try {
    const secret = APP_PROXY_SECRET;
    if (!secret) return false;

    const url = new URL(req.originalUrl, `https://${req.headers.host}`);
    const params = new URLSearchParams(url.search);

    // Shopify peut envoyer 'signature' (App Proxy) ou 'hmac' (rare via proxy)
    const sig = params.get("signature") || params.get("hmac");
    if (!sig) return false;

    params.delete("signature");
    params.delete("hmac");

    // 1) Query canoniquement triée + encodée
    const sortedQuery = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    // Essai A : HMAC(query)
    const hA = crypto.createHmac("sha256", secret).update(sortedQuery).digest("hex");
    if (safeEq(hA, sig)) {
      console.log(`[Proxy HMAC] ok via query | digA=${hA.slice(0, 8)} | sig=${sig.slice(0, 8)}`);
      return true;
    }

    // 2) Essai B : HMAC(path(proxy) + '?' + query)
    const prefix = params.get("path_prefix") || ""; // ex: /apps/logtek-split
    const proxyPath = `${prefix}${req.path}`;      // ex: /apps/logtek-split/prepare
    const base = sortedQuery ? `${proxyPath}?${sortedQuery}` : proxyPath;

    const hB = crypto.createHmac("sha256", secret).update(base).digest("hex");
    const okB = safeEq(hB, sig);

    console.log(`[Proxy HMAC] try A/B | okA=false | okB=${okB} | base='${base}' | digB=${hB.slice(0, 8)} | sig=${sig.slice(0, 8)}`);
    return okB;
  } catch (e) {
    console.error("Proxy verification error:", e);
    return false;
  }
}

// Appel GraphQL Admin (si besoin plus tard)
async function adminGraphQL(query, variables = {}) {
  if (!SHOPIFY_ADMIN_TOKEN || !SHOPIFY_SHOP_DOMAIN) {
    throw new Error("SHOPIFY_ADMIN_TOKEN / SHOPIFY_SHOP_DOMAIN non configurés");
  }
  const res = await fetch(`https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!res.ok) throw new Error(`AdminGraphQL HTTP ${res.status}`);
  return res.json();
}

// ----- Routes -----

app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true, service: "logtek-split", ts: Date.now() });
});

app.get("/", (_req, res) => {
  res.status(200).send("logtek-split up");
});

// App Proxy: /apps/logtek-split/prepare  --> Express: GET /prepare
app.get("/prepare", async (req, res) => {
  if (!verifyProxySignature(req)) {
    return res.status(403).json({ error: "Invalid proxy signature" });
  }

  // Ici tu peux ajouter ta logique (lecture panier côté JS, etc.)
  // Pour l’instant on retourne un OK simple.
  return res.json({ ok: true, msg: "proxy verified" });
});

// (Optionnel) route de test admin
app.get("/me", async (req, res) => {
  try {
    const q = `query { shop { name myshopifyDomain } }`;
    const data = await adminGraphQL(q);
    res.json({ ok: true, data });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ----- Boot -----
app.listen(PORT, () => {
  console.log("////////////////////////////////////////////////////");
  console.log(`==> Service running on port ${PORT}`);
  console.log("////////////////////////////////////////////////////");
});
