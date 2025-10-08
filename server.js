// server.js — Logtek Split (Express + Shopify App Proxy) — Node 18+/Render
// ----------------------------------------------------------------------------
import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
console.log("Logtek split — HMAC v6 loaded");




const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== ENV ====================================================================
const SHOP             = process.env.SHOPIFY_SHOP_DOMAIN;      // ex: 2uvcbu-ci.myshopify.com
const ADMIN_TOKEN      = process.env.SHOPIFY_ADMIN_TOKEN;      // Admin API token (shpat_…)
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN; // Storefront API token
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET;         // App secret key (Partner dashboard)
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";
const FROM_EMAIL       = process.env.FROM_EMAIL || "no-reply@logtek.ca";
const PORT             = process.env.PORT || 10000;

if (!SHOP || !ADMIN_TOKEN || !APP_PROXY_SECRET) {
  console.warn("[WARN] Variables d'env manquantes (SHOP/ADMIN_TOKEN/APP_PROXY_SECRET).");
}

// ===== Fournisseurs (exemple) =================================================
const VENDORS = [
  { vendor_id: "centre-routier",   name: "Le Centre Routier",   po_email: "commandes@centreroutier.ca" },
  { vendor_id: "carrefour-camion", name: "Carrefour du Camion", po_email: "achat@carrefourcamion.ca" },
  { vendor_id: "flextral",         name: "Hose Flextral",       po_email: "orders@flextral.ca" }
];

// ===== Utils ==================================================================
const escapeHtml = (s) =>
  (s || "").toString().replace(/[&<>"']/g, (m) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[m]));

// ====== HMAC App Proxy — variantes encodées & RAW triées ======================
// ===== HMAC App Proxy — v4 (encoded/raw + express path + PROXY path) =========
// ===== HMAC App Proxy — v5 (encoded, rawSorted, rawOriginal, proxy path) ======
// ===== HMAC App Proxy — v6 (encoded, rawSorted, rawOriginal, proxy path, prefix-only, legacy md5) =====
function safeHmacEq(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
  catch { return false; }
}

function canonicalEncoded(paramsObj) {
  const pairs = [];
  for (const [k, v] of paramsObj.entries()) pairs.push([k, v]);
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  return pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

// RAW + triée
function canonicalRawSorted(queryString) {
  if (!queryString) return "";
  const segs = queryString.split("&").filter(Boolean).map(seg => {
    const i = seg.indexOf("=");
    const kRaw = i >= 0 ? seg.slice(0, i) : seg;
    let kDec;
    try { kDec = decodeURIComponent(kRaw); } catch { kDec = kRaw; }
    return { raw: seg, kDec };
  }).filter(p => p.kDec !== "hmac" && p.kDec !== "signature");
  segs.sort((a, b) => a.kDec.localeCompare(b.kDec));
  return segs.map(p => p.raw).join("&");
}

// RAW + ordre d’origine (sans tri)
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

// Variante: RAW d’origine mais en retirant path_prefix (au cas où Shopify ne le signe pas)
function rawOriginalMinusPathPrefix(queryString) {
  if (!queryString) return "";
  const out = [];
  for (const seg of queryString.split("&")) {
    if (!seg) continue;
    const i = seg.indexOf("=");
    const kRaw = i >= 0 ? seg.slice(0, i) : seg;
    let kDec;
    try { kDec = decodeURIComponent(kRaw); } catch { kDec = kRaw; }
    if (kDec === "hmac" || kDec === "signature" || kDec === "path_prefix") continue;
    out.push(seg);
  }
  return out.join("&");
}

function verifyProxySignature(req) {
  const full     = req.originalUrl || "";
  const rawPath  = full.split("?")[0] || "";
  const qStr     = full.includes("?") ? full.split("?")[1] : "";

  const urlParams = new URLSearchParams(qStr);
  const providedHmac = urlParams.get("hmac");
  const providedSig  = urlParams.get("signature"); // legacy
  const provided     = providedHmac || providedSig;
  if (!provided) { console.log("[Proxy v6] aucun hmac/signature"); return false; }

  // Prépare les variantes de query
  const encQ   = (() => { const p = new URLSearchParams(qStr); p.delete("hmac"); p.delete("signature"); return canonicalEncoded(p); })();
  const rawQ   = canonicalRawSorted(qStr);
  const rawOri = rawOriginalWithoutSig(qStr);
  const rawOriNoPrefix = rawOriginalMinusPathPrefix(qStr);

  // Chemins
  const expressPath   = req.path || rawPath || "/prepare";             // "/prepare"
  const proxyPrefix   = "/apps";
  const proxySub      = "/logtek-split";
  const proxyPath     = `${proxyPrefix}${proxySub}${expressPath}`;     // "/apps/logtek-split/prepare"
  const proxyRootPath = `${proxyPrefix}${proxySub}`;                   // "/apps/logtek-split"

  const show = (s) => (s || "").toString().slice(0, 140);

  console.log(`[Proxy v6] expressPath="${expressPath}" proxyPath="${proxyPath}" rawPath="${rawPath}" used="${providedHmac ? 'hmac' : 'signature'}"`);
  console.log(`[Proxy v6] encQ="${show(encQ)}"`);
  console.log(`[Proxy v6] rawQ="${show(rawQ)}"`);
  console.log(`[Proxy v6] rawOri="${show(rawOri)}" rawOriNoPrefix="${show(rawOriNoPrefix)}"`);

  // Candidats HMAC-SHA256 (nouveau format)
  const hmacCandidates = [
    // query seule
    { label: "H256 encoded:query",              data: encQ },
    { label: "H256 rawSorted:query",            data: rawQ },
    { label: "H256 rawOriginal:query",          data: rawOri },
    { label: "H256 rawOriginalNoPrefix:query",  data: rawOriNoPrefix },

    // path express
    { label: "H256 encoded:path(express)",      data: encQ   ? `${expressPath}?${encQ}`     : expressPath },
    { label: "H256 rawSorted:path(express)",    data: rawQ   ? `${expressPath}?${rawQ}`     : expressPath },
    { label: "H256 rawOriginal:path(express)",  data: rawOri ? `${expressPath}?${rawOri}`   : expressPath },
    { label: "H256 rawOriginalNoPrefix:path(express)", data: rawOriNoPrefix ? `${expressPath}?${rawOriNoPrefix}` : expressPath },

    // path proxy COMPLET
    { label: "H256 encoded:path(proxy)",        data: encQ   ? `${proxyPath}?${encQ}`       : proxyPath },
    { label: "H256 rawSorted:path(proxy)",      data: rawQ   ? `${proxyPath}?${rawQ}`       : proxyPath },
    { label: "H256 rawOriginal:path(proxy)",    data: rawOri ? `${proxyPath}?${rawOri}`     : proxyPath },
    { label: "H256 rawOriginalNoPrefix:path(proxy)", data: rawOriNoPrefix ? `${proxyPath}?${rawOriNoPrefix}` : proxyPath },

    // path proxy **racine** (sans /prepare) — certains thèmes signent ça
    { label: "H256 encoded:path(proxyRoot)",        data: encQ   ? `${proxyRootPath}?${encQ}`       : proxyRootPath },
    { label: "H256 rawOriginal:path(proxyRoot)",    data: rawOri ? `${proxyRootPath}?${rawOri}`     : proxyRootPath },
    { label: "H256 rawOriginalNoPrefix:path(proxyRoot)", data: rawOriNoPrefix ? `${proxyRootPath}?${rawOriNoPrefix}` : proxyRootPath },
  ];

  for (const v of hmacCandidates) {
    const digest = crypto.createHmac("sha256", APP_PROXY_SECRET).update(v.data).digest("hex");
    const ok = safeHmacEq(digest, provided);
    console.log(`[Proxy v6] try=${v.label} | base="${show(v.data)}" | digest8=${digest.slice(0,8)} | prov8=${provided.slice(0,8)} | ok=${ok}`);
    if (ok) return true;
  }

  // Fallback LEGACY MD5 si Shopify envoie encore "signature" (très rare, mais on couvre)
  if (providedSig && !providedHmac) {
    const md5Candidates = [
      `${rawOri}`, `${encQ}`,
      `${expressPath}?${rawOri}`, `${expressPath}?${encQ}`,
      `${proxyPath}?${rawOri}`,   `${proxyPath}?${encQ}`,
      `${proxyRootPath}?${rawOri}`, `${proxyRootPath}?${encQ}`,
    ].filter(Boolean);
    for (const base of md5Candidates) {
      const digest = crypto.createHash("md5").update(APP_PROXY_SECRET + base).digest("hex");
      const ok = safeHmacEq(digest, providedSig);
      console.log(`[Proxy v6] LEGACY md5 | base="${show(base)}" | digest8=${digest.slice(0,8)} | prov8=${providedSig.slice(0,8)} | ok=${ok}`);
      if (ok) return true;
    }
  }

  return false;
}



// ==============================================================================

// ===== Admin GraphQL helper ===================================================
async function adminGraphQL(query, variables) {
  const r = await fetch(`https://${SHOP}/admin/api/2025-01/graphql.json`, {
    method: "POST",
    headers: { "X-Shopify-Access-Token": ADMIN_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables })
  });
  return r.json();
}

// ===== Metafields produits ====================================================
async function fetchProductsMetafields(productIds) {
  if (!productIds?.length) return new Map();
  const ids = productIds.map((id) => `gid://shopify/Product/${id}`);
  const query = `
    query($ids:[ID!]!){
      nodes(ids:$ids){
        ... on Product {
          id
          m1: metafield(namespace:"logtek", key:"account_eligible"){ value }
          m2: metafield(namespace:"logtek", key:"vendor_id"){ value }
        }
      }
    }`;
  const r = await adminGraphQL(query, { ids });
  const out = new Map();
  for (const n of r?.data?.nodes || []) {
    if (!n) continue;
    const pid = Number(n.id.split("/").pop());
    out.set(pid, { account_eligible: n?.m1?.value || "false", vendor_id: n?.m2?.value || null });
  }
  return out;
}

// ===== Comptes fournisseurs client ===========================================
async function fetchCustomerVendorAccounts(customerId) {
  if (!customerId) return [];
  const gid = `gid://shopify/Customer/${customerId}`;
  const q = `
    query($id:ID!){
      customer(id:$id){
        v: metafield(namespace:"logtek", key:"vendor_accounts"){ value }
      }
    }`;
  const r = await adminGraphQL(q, { id: gid });
  const raw = r?.data?.customer?.v?.value || "[]";
  try { return JSON.parse(raw); } catch { return []; }
}

// ===== Split par fournisseur / conditions =====================================
function splitByVendorAndTerms(lines, vendorMap) {
  const groups = new Map();
  const payNow = [];
  for (const l of lines) {
    const hasAccount = l.vendorId && vendorMap.has(l.vendorId);
    const canAccount = hasAccount && l.accountEligible;
    if (canAccount) {
      if (!groups.has(l.vendorId)) groups.set(l.vendorId, []);
      groups.get(l.vendorId).push(l);
    } else {
      payNow.push(l);
    }
  }
  const onAccountGroups = Array.from(groups.entries()).map(([vendorId, lines]) => ({
    vendorId, lines, account: vendorMap.get(vendorId) || null
  }));
  return { onAccountGroups, payNowLines: payNow };
}

// ===== Draft order “au compte” ===============================================
async function createDraftOrderOnAccount(group, customerId) {
  const line_items = group.lines.map((l) => ({ variant_id: l.variantId, quantity: l.quantity }));
  const payload = {
    draft_order: {
      line_items,
      customer: customerId ? { id: customerId } : undefined,
      tags: ["On Account", `Vendor:${group.vendorId}`],
      note_attributes: [
        { name: "Vendor", value: group.vendorId },
        { name: "Account No", value: group.account?.account_no || "" },
        { name: "Type", value: "Au compte" }
      ],
      use_customer_default_address: true
    }
  };
  const resp = await fetch(`https://${SHOP}/admin/api/2025-01/draft_orders.json`, {
    method: "POST",
    headers: { "X-Shopify-Access-Token": ADMIN_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).then((x) => x.json());
  return resp?.draft_order || null;
}

// ===== Checkout “pay now” (Storefront) =======================================
async function createPayNowCheckout(payNowLines) {
  const lineItems = payNowLines.map((l) => ({
    quantity: l.quantity,
    variantId: `gid://shopify/ProductVariant/${l.variantId}`
  }));
  const query = `
    mutation checkoutCreate($input: CheckoutCreateInput!){
      checkoutCreate(input:$input){
        checkout { webUrl }
        userErrors { field message }
      }
    }`;
  const variables = { input: { lineItems } };
  const r = await fetch(`https://${SHOP}/api/2023-10/graphql.json`, {
    method: "POST",
    headers: { "X-Shopify-Storefront-Access-Token": STOREFRONT_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables })
  }).then((x) => x.json());
  if (r?.data?.checkoutCreate?.userErrors?.length) {
    console.error("Storefront checkoutCreate errors:", r.data.checkoutCreate.userErrors);
  }
  return r?.data?.checkoutCreate?.checkout?.webUrl || null;
}

// ===== Health =================================================================
app.get("/health", (_req, res) => res.status(200).send("ok"));

// ===== GET /prepare — test navigateur via App Proxy ===========================
app.get("/prepare", (req, res) => {
  if (!verifyProxySignature(req)) return res.status(401).json({ error: "Invalid proxy signature" });
  return res.status(200).json({ error: "Panier vide" });
});

// ===== POST /prepare — flux réel depuis le thème ==============================
app.post("/prepare", async (req, res) => {
  try {
    if (!verifyProxySignature(req)) return res.status(401).json({ error: "Invalid proxy signature" });

    const { customerId, items } = req.body || {};
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Panier vide" });
    }

    // 1) Metafields produits
    const productIds = [...new Set(items.map(i => i.product_id))];
    const metas = await fetchProductsMetafields(productIds);

    // 2) Comptes fournisseurs du client
    const accounts = await fetchCustomerVendorAccounts(customerId);
    const mapAcc = new Map(accounts.map(a => [a.vendor_id, a]));

    // 3) Enrichir lignes
    const enrich = items.map(i => {
      const m = metas.get(i.product_id) || {};
      return {
        productId: i.product_id,
        variantId: i.variant_id,
        quantity: i.quantity,
        accountEligible: m.account_eligible === "true" || m.account_eligible === true,
        vendorId: m.vendor_id || null
      };
    });

    // 4) Split
    const { onAccountGroups, payNowLines } = splitByVendorAndTerms(enrich, mapAcc);

    // 5) Draft Orders + (option) email PO
    const onAccountSummary = [];
    for (const grp of onAccountGroups) {
      const draft = await createDraftOrderOnAccount(grp, customerId);
      onAccountSummary.push({
        vendor_id: grp.vendorId,
        draft_order_id: draft?.id,
        po_number: draft?.name || "",
        total: draft?.total_price || ""
      });
    }

    // 6) Checkout pay-now
    let payNowCheckoutUrl = null;
    if (payNowLines.length) payNowCheckoutUrl = await createPayNowCheckout(payNowLines);

    return res.status(200).json({
      summary: { onAccount: onAccountSummary, payNow: { lines: payNowLines.length } },
      payNowCheckoutUrl
    });
  } catch (e) {
    console.error("Server error:", e);
    return res.status(500).json({ error: "Server error" });
  }
});

// ===== Start ==================================================================
app.listen(PORT, () => {
  console.log(`Logtek split server on :${PORT}`);
});
