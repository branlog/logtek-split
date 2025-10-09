// server.js — Logtek Split (Express + Shopify App Proxy) — FINAL
// Node 18+ (ESM). Assurez-vous que package.json contient "type": "module"

import express from "express";
import crypto from "crypto";
import process from "process";
import fetch from "node-fetch"; // utile pour la suite (Admin/Storefront) — OK si déjà installé

const app = express();
app.set("trust proxy", true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ====== ENV ======
const PORT = parseInt(process.env.PORT || "10000", 10);
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET || "";
const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN || "";
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN || "";

// ====== LOG BOOT ======
console.log("Logtek split — server FINAL loaded");
console.log("Env check → APP_PROXY_SECRET:", APP_PROXY_SECRET ? "✓ set" : "✗ missing");
console.log("Env check → SHOPIFY_SHOP_DOMAIN:", SHOPIFY_SHOP_DOMAIN || "(missing)");
console.log("Env check → PORT:", PORT);

// ====== HMAC HELPERS (robuste) ======
function safeEq(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
  catch { return false; }
}
const encRFC = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

function qs_sorted_encoded(params) {
  const arr = Array.from(params.entries());
  arr.sort((a,b)=>a[0].localeCompare(b[0]));
  return arr.map(([k,v])=>`${encRFC(k)}=${encRFC(v)}`).join("&");
}
function qs_sorted_raw(params) {
  const arr = Array.from(params.entries());
  arr.sort((a,b)=>a[0].localeCompare(b[0]));
  return arr.map(([k,v])=>`${k}=${v}`).join("&");
}
function qs_raw(params) { return params.toString(); }

// RAW + triée (on garde les segments bruts, tri par clé décodée)
function canonicalRawSorted(queryString) {
  if (!queryString) return "";
  const segs = queryString.split("&").filter(Boolean).map(seg => {
    const i = seg.indexOf("=");
    const kRaw = i >= 0 ? seg.slice(0, i) : seg;
    let kDec;
    try { kDec = decodeURIComponent(kRaw); } catch { kDec = kRaw; }
    return { raw: seg, kDec };
  }).filter(p => p.kDec !== "hmac" && p.kDec !== "signature");
  segs.sort((a,b)=>a.kDec.localeCompare(b.kDec));
  return segs.map(p => p.raw).join("&");
}

// RAW ordre d’origine (sans tri), on retire juste hmac/signature
function rawOriginalWithoutSig(queryString) {
  if (!queryString) return "";
  const out = [];
  for (const seg of queryString.split("&")) {
    if (!seg) continue;
    const i = seg.indexOf("=");
    const kRaw = i >= 0 ? seg.slice(0, i) : seg;
    let kDec;
    try { kDec = decodeURIComponent(kRaw); } catch { kDec = kRaw; }
    if (kDec === "hmac" || kDec === "signature") continue;
    out.push(seg);
  }
  return out.join("&");
}

// ====== VÉRIFICATION SIGNATURE APP PROXY ======
function verifyProxySignature(req) {
  try {
    if (!APP_PROXY_SECRET) {
      console.log("[Proxy] SECRET manquant");
      return false;
    }

    const original = req.originalUrl || req.url || "";
    const pathOnly = original.split("?")[0] || "/prepare";
    const qs = original.includes("?") ? original.split("?")[1] : "";

    const paramsAll = new URLSearchParams(qs);
    const providedHmac = paramsAll.get("hmac");
    const providedSig  = paramsAll.get("signature"); // legacy
    const provided = providedHmac || providedSig;
    if (!provided) {
      console.log("[Proxy] ni hmac ni signature dans la requête");
      return false;
    }

    // Enlever les clefs de signature pour recalculer
    paramsAll.delete("hmac"); paramsAll.delete("signature");

    // Variantes de query (3 façons)
    const q_raw   = qs_raw(paramsAll);     // ordre d’origine (URLSearchParams préserve l’ordre d’insertion)
    const q_sraw  = qs_sorted_raw(paramsAll);
    const q_senc  = qs_sorted_encoded(paramsAll);

    // Variantes "RAW exactes" (depuis la query telle qu’arrivée)
    const q_rawSorted = canonicalRawSorted(qs);
    const q_rawOri    = rawOriginalWithoutSig(qs);

    // Chemins : Express et Proxy complet (en fonction de ta config proxy apps/logtek-split)
    const expressPath = req.path || pathOnly;                // ex: "/prepare"
    const proxyPath   = `/apps/logtek-split${expressPath}`;  // ex: "/apps/logtek-split/prepare"
    const proxyRoot   = `/apps/logtek-split`;                // parfois Shopify signe la racine

    const show = (s) => (s || "").toString().slice(0, 160);

    // ---- HMAC-SHA256 (moderne) ----
    if (providedHmac) {
      const forms = [
        // Query seule (différentes reconstructions)
        { L:"H256 Q raw",    B: q_raw },
        { L:"H256 Q sraw",   B: q_sraw },
        { L:"H256 Q senc",   B: q_senc },
        { L:"H256 Q rawSorted", B: q_rawSorted },
        { L:"H256 Q rawOri", B: q_rawOri },

        // Path express
        { L:"H256 PE raw",   B: q_raw ? `${expressPath}?${q_raw}` : expressPath },
        { L:"H256 PE sraw",  B: q_sraw ? `${expressPath}?${q_sraw}` : expressPath },
        { L:"H256 PE senc",  B: q_senc ? `${expressPath}?${q_senc}` : expressPath },
        { L:"H256 PE rawSorted", B: q_rawSorted ? `${expressPath}?${q_rawSorted}` : expressPath },
        { L:"H256 PE rawOri",B: q_rawOri ? `${expressPath}?${q_rawOri}` : expressPath },

        // Path proxy COMPLET
        { L:"H256 PP raw",   B: q_raw ? `${proxyPath}?${q_raw}` : proxyPath },
        { L:"H256 PP sraw",  B: q_sraw ? `${proxyPath}?${q_sraw}` : proxyPath },
        { L:"H256 PP senc",  B: q_senc ? `${proxyPath}?${q_senc}` : proxyPath },
        { L:"H256 PP rawSorted", B: q_rawSorted ? `${proxyPath}?${q_rawSorted}` : proxyPath },
        { L:"H256 PP rawOri",B: q_rawOri ? `${proxyPath}?${q_rawOri}` : proxyPath },

        // Path proxy RACINE (au cas où)
        { L:"H256 PPR raw",  B: q_raw ? `${proxyRoot}?${q_raw}` : proxyRoot },
        { L:"H256 PPR rawOri", B: q_rawOri ? `${proxyRoot}?${q_rawOri}` : proxyRoot },
        { L:"H256 PPR sraw", B: q_sraw ? `${proxyRoot}?${q_sraw}` : proxyRoot },
      ];

      for (const f of forms) {
        const digest = crypto.createHmac("sha256", APP_PROXY_SECRET).update(f.B).digest("hex");
        const ok = safeEq(digest, providedHmac);
        console.log(`[Proxy] ${f.L} | base="${show(f.B)}" | d8=${digest.slice(0,8)} | p8=${providedHmac.slice(0,8)} | ok=${ok}`);
        if (ok) return true;
      }
    }

    // ---- LEGACY MD5 (si Shopify envoie encore "signature" et PAS "hmac") ----
    if (!providedHmac && providedSig) {
      const bases = [
        q_raw, q_sraw, q_senc, q_rawSorted, q_rawOri,
        `${expressPath}?${q_raw}`, `${expressPath}?${q_sraw}`, `${expressPath}?${q_senc}`, `${expressPath}?${q_rawSorted}`, `${expressPath}?${q_rawOri}`,
        `${proxyPath}?${q_raw}`, `${proxyPath}?${q_sraw}`, `${proxyPath}?${q_senc}`, `${proxyPath}?${q_rawSorted}`, `${proxyPath}?${q_rawOri}`,
        `${proxyRoot}?${q_raw}`, `${proxyRoot}?${q_sraw}`, `${proxyRoot}?${q_senc}`, `${proxyRoot}?${q_rawSorted}`, `${proxyRoot}?${q_rawOri}`,
      ].filter(Boolean);

      for (const base of bases) {
        const digest = crypto.createHash("md5").update(APP_PROXY_SECRET + base).digest("hex");
        const ok = safeEq(digest, providedSig);
        console.log(`[Proxy] MD5 | base="${show(base)}" | d8=${digest.slice(0,8)} | p8=${providedSig.slice(0,8)} | ok=${ok}`);
        if (ok) return true;
      }
    }

    console.log("[Proxy] aucune variante ne matche → 401");
    return false;
  } catch (e) {
    console.log("[Proxy] exception verify:", e?.message || e);
    return false;
  }
}

// Middleware de protection App Proxy
function requireProxySignature(req, res, next) {
  const ok = verifyProxySignature(req);
  if (!ok) return res.status(401).json({ error: "Invalid proxy signature" });
  next();
}

// ====== HEALTH ======
app.get("/health", (_req, res) => res.status(200).send("ok"));

// ====== PREPARE (GET pour test navigateur) ======
app.get("/prepare", requireProxySignature, (req, res) => {
  // Test attendu : si aucun body/panier → {"error":"Panier vide"}
  return res.status(200).json({ error: "Panier vide" });
});

// ====== PREPARE (POST pour flux réel depuis le thème) ======
app.post("/prepare", requireProxySignature, async (req, res) => {
  try {
    const { customerId, items } = req.body || {};
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Panier vide" });
    }
    // Ici tu brancheras la logique split (draft orders par fournisseur, checkout pay-now, etc.)
    return res.status(200).json({ ok: true, received: { customerId, itemsCount: items.length } });
  } catch (e) {
    console.error("POST /prepare error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// ====== 404 ======
app.use((_req, res) => res.status(404).send("Not Found"));

// ====== START ======
app.listen(PORT, () => {
  console.log(`Logtek split server running on :${PORT}`);
});
