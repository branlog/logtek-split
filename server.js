// server.js — Logtek Split (Express + Shopify App Proxy) - Node 18+ / Render
// Remplace entièrement ton server.js par ce fichier.

import express from "express";
import fetch from "node-fetch"; // si tu n'as pas node-fetch, installe: npm i node-fetch
import crypto from "crypto";
import process from "process";

const app = express();
app.set("trust proxy", true); // si déployé derrière un reverse proxy

// --- Config depuis env ---
const PORT = parseInt(process.env.PORT || process.env.PORT_NUMBER || "10000", 10) || 10000;
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET || "";
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN || "";
const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN || "";

/* -----------------------
   Helpers HMAC / canonical
   ----------------------- */
function safeTimingEq(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
  catch (e) { return false; }
}

function encodeRFC3986(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function toHexDigest(secret, message) {
  return crypto.createHmac("sha256", secret).update(message).digest("hex");
}

function buildPairsFrom(searchParams) {
  const pairs = [];
  for (const [k, v] of searchParams.entries()) pairs.push([k, v]);
  return pairs;
}

function canonical_sorted_encoded(paramsObj) {
  const pairs = buildPairsFrom(paramsObj);
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  return pairs.map(([k, v]) => `${encodeRFC3986(k)}=${encodeRFC3986(v)}`).join("&");
}

function canonical_sorted_raw(paramsObj) {
  const pairs = buildPairsFrom(paramsObj);
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

function canonical_raw(paramsObj) {
  return paramsObj.toString();
}

/**
 * verifyProxySignature(req)
 * - Essaie plusieurs canonicals plausibles (query, sorted, encoded, path+query)
 * - Logue tous les essais (pour debug)
 * - Retourne true si match, false sinon
 */
export function verifyProxySignature(req) {
  try {
    const secret = APP_PROXY_SECRET;
    if (!secret) {
      console.log("[Proxy HMAC] APP_PROXY_SECRET manquant !");
      return false;
    }

    const original = req.originalUrl || req.url || "";
    const full = String(original);
    const queryString = full.includes("?") ? full.split("?")[1] : "";
    const params = new URLSearchParams(queryString || "");
    const hmac = params.get("hmac");
    if (!hmac) {
      console.log("[Proxy HMAC] pas de param hmac dans la requête");
      return false;
    }

    // On enlève hmac pour reconstruire les canonicals
    params.delete("hmac");

    const shop = params.get("shop") || "";
    const timestamp = params.get("timestamp") || "";
    const request_hmac8 = (hmac || "").slice(0, 8);

    const candidates = [];

    // 1) query-only
    candidates.push({ label: "rawQuery", str: canonical_raw(params) });
    candidates.push({ label: "sortedRawQuery", str: canonical_sorted_raw(params) });
    candidates.push({ label: "sortedEncodedQuery", str: canonical_sorted_encoded(params) });

    // 2) path variants
    const expressPath = (req.path || req.url?.split("?")[0] || "/").toString();
    const proxyPath = (req.proxyPath || ""); // si tu veux populate req.proxyPath ailleurs
    const pathCandidates = [
      { label: "path+rawQuery", prefix: expressPath, body: canonical_raw(params) },
      { label: "path+sortedRawQuery", prefix: expressPath, body: canonical_sorted_raw(params) },
      { label: "path+sortedEncodedQuery", prefix: expressPath, body: canonical_sorted_encoded(params) },
      { label: "proxyPath+rawQuery", prefix: proxyPath || expressPath, body: canonical_raw(params) },
      { label: "proxyPath+sortedRawQuery", prefix: proxyPath || expressPath, body: canonical_sorted_raw(params) },
      { label: "proxyPath+sortedEncodedQuery", prefix: proxyPath || expressPath, body: canonical_sorted_encoded(params) },
    ];
    for (const c of pathCandidates) {
      const p = (c.prefix || "").toString();
      const norm = p.endsWith("/") && p.length > 1 ? p.slice(0, -1) : p;
      const b = c.body ? (c.body.length ? `${norm}?${c.body}` : `${norm}`) : `${norm}`;
      candidates.push({ label: c.label, str: b });
    }

    // 3) original raw QS (ordering & encoding exact)
    if (queryString) candidates.push({ label: "originalRawQS", str: queryString });

    // Test each candidate
    for (const c of candidates) {
      const digest = toHexDigest(secret, c.str);
      const ok = safeTimingEq(digest, hmac);
      console.log(`[Proxy HMAC] try=${c.label} | base="${c.str.length>160?c.str.slice(0,160)+'...':c.str}" | digest8=${digest.slice(0,8)} | req8=${request_hmac8} | ok=${ok}`);
      if (ok) {
        console.log(`[Proxy HMAC] VALID (${c.label}) shop=${shop} timestamp=${timestamp}`);
        return true;
      }
    }

    console.log("[Proxy HMAC] aucun candidat n'a matché -> rejet");
    return false;
  } catch (err) {
    console.log("[Proxy HMAC] exception verify:", err?.message || err);
    return false;
  }
}

/* -----------------------
   Middlewares & Routes
   ----------------------- */

// Middleware simple pour vérifier le proxy HMAC sur les routes d'app proxy
function requireProxySignature(req, res, next) {
  const ok = verifyProxySignature(req);
  if (!ok) {
    res.status(401).json({ error: "Invalid proxy signature" });
    return;
  }
  next();
}

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "logtek-split" });
});

// Endpoint d'app proxy: /prepare
// Shopify envoie la requête GET vers /prepare (proxy path -> /apps/logtek-split/prepare)
app.get("/prepare", requireProxySignature, express.urlencoded({ extended: true }), async (req, res) => {
  // Shopify app proxy souvent n'envoie pas le panier JSON — on retourne l'erreur de test si rien.
  // Comportement de test demandé : renvoyer {"error":"Panier vide"} si pas de body/cart.
  // Si tu veux plus de logique (ex: récupérer le checkout / draft order), ajoute ici.
  try {
    // On regarde si la requête contient des infos de panier (exemple : line_items, cart_token, etc.)
    // Ici on fait un test basique : si query contient "cart" ou "items" -> ok, sinon on renvoie erreur
    const q = req.query || {};
    const hasCart = (() => {
      if (Object.keys(q).length === 0) return false;
      // si un param contient 'items' ou 'cart' ou 'checkout' ou 'logged_in_customer_id' non vide -> considérer comme présent
      const keys = Object.keys(q).join(" ").toLowerCase();
      if (keys.includes("items") || keys.includes("cart") || keys.includes("checkout")) return true;
      if ((q.logged_in_customer_id || "").length > 0) return true;
      return false;
    })();

    if (!hasCart) {
      // réponse de test demandée
      return res.json({ error: "Panier vide" });
    }

    // Sinon, placeholder: renvoyer OK (à adapter selon ta logique métier)
    return res.json({ ok: true, note: "Proxy validé et payload reçu", query: q });
  } catch (err) {
    console.error("Error /prepare:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/* Optionnel: route pour debug signer localement (ne pas exposer en prod) */
// app.get("/_debug/sign/:message", (req, res) => {
//   const m = req.params.message || "";
//   const digest = toHexDigest(APP_PROXY_SECRET, m);
//   res.json({ message: m, digest });
// });

/* 404 */
app.use((req, res) => {
  res.status(404).send("Not Found");
});

/* Start */
app.listen(PORT, () => {
  console.log(`==> Available at your primary URL (port ${PORT})`);
  console.log(`==> Detected service running on port ${PORT}`);
  console.log("==> APP_PROXY_SECRET set?", !!APP_PROXY_SECRET);
  console.log("==> SHOPIFY_SHOP_DOMAIN:", SHOPIFY_SHOP_DOMAIN || "(not set)");
});

