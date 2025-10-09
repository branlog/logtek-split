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
function safeEq(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
  catch { return false; }
}
const enc = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

function sortEncoded(params) {
  const arr = Array.from(params.entries());
  arr.sort((a,b)=>a[0].localeCompare(b[0]));
  return arr.map(([k,v])=>`${enc(k)}=${enc(v)}`).join("&");
}
function sortRaw(params) {
  const arr = Array.from(params.entries());
  arr.sort((a,b)=>a[0].localeCompare(b[0]));
  return arr.map(([k,v])=>`${k}=${v}`).join("&");
}
function rawQS(params) { return params.toString(); }

export function verifyProxySignature(req) {
  const SECRET = process.env.APP_PROXY_SECRET || "";
  if (!SECRET) { console.log("[Proxy] SECRET manquant"); return false; }

  const original = req.originalUrl || req.url || "";
  const pathOnly = original.split("?")[0] || "/prepare";
  const qs       = original.includes("?") ? original.split("?")[1] : "";

  const pAll = new URLSearchParams(qs);
  const providedHmac = pAll.get("hmac");
  const providedSig  = pAll.get("signature"); // legacy
  if (!providedHmac && !providedSig) {
    console.log("[Proxy] ni hmac ni signature dans la requête");
    return false;
  }

  // on enlève les params de signature pour recalculer
  pAll.delete("hmac"); pAll.delete("signature");

  // pré-calculs
  const q_raw    = rawQS(pAll);          // ordre d'origine
  const q_sraw   = sortRaw(pAll);        // trié non-encodé
  const q_senc   = sortEncoded(pAll);    // trié encodé
  const expressP = req.path || pathOnly; // ex: "/prepare"
  const proxyP   = `/apps/logtek-split${expressP}`; // ex: "/apps/logtek-split/prepare"

  const forms = [
    // query seule
    { label:"Q raw",     data:q_raw },
    { label:"Q sraw",    data:q_sraw },
    { label:"Q senc",    data:q_senc },
    // path express
    { label:"PE raw",    data: q_raw ? `${expressP}?${q_raw}` : expressP },
    { label:"PE sraw",   data: q_sraw ? `${expressP}?${q_sraw}` : expressP },
    { label:"PE senc",   data: q_senc ? `${expressP}?${q_senc}` : expressP },
    // path proxy complet
    { label:"PP raw",    data: q_raw ? `${proxyP}?${q_raw}` : proxyP },
    { label:"PP sraw",   data: q_sraw ? `${proxyP}?${q_sraw}` : proxyP },
    { label:"PP senc",   data: q_senc ? `${proxyP}?${q_senc}` : proxyP },
  ];

  // 1) cas moderne: HMAC-SHA256 dans "hmac"
  if (providedHmac) {
    for (const f of forms) {
      const digest = crypto.createHmac("sha256", SECRET).update(f.data).digest("hex");
      const ok = safeEq(digest, providedHmac);
      console.log(`[Proxy] H256 try=${f.label} | d8=${digest.slice(0,8)} | p8=${providedHmac.slice(0,8)} | ok=${ok}`);
      if (ok) return true;
    }
  }

  // 2) fallback legacy: "signature" (MD5 de secret + baseString) — rare mais supporté
  if (providedSig && !providedHmac) {
    for (const f of forms) {
      const digest = crypto.createHash("md5").update(SECRET + f.data).digest("hex");
      const ok = safeEq(digest, providedSig);
      console.log(`[Proxy] MD5 try=${f.label} | d8=${digest.slice(0,8)} | p8=${providedSig.slice(0,8)} | ok=${ok}`);
      if (ok) return true;
    }
  }

  return false;
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

