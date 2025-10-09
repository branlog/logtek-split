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
import crypto from "crypto";

/**
 * Remplaçant robuste pour verifyProxySignature(req)
 * - lit la query de req.originalUrl || req.url
 * - extrait la valeur "hmac" envoyée par Shopify
 * - recrée plusieurs canonicals plausibles (encodées / non-encodées, triées)
 * - calcule HMAC-SHA256(hex) avec process.env.APP_PROXY_SECRET
 * - compare en timing-safe
 *
 * Retourne true si une variante correspond, false sinon.
 * Logs détaillés pour debugging (inspecter dans Render logs).
 */
function safeTimingEq(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
  catch (e) { return false; }
}

function encodeRFC3986(str) {
  // encodeURIComponent mais remplace quelques caractères pour être plus strict RFC3986
  return encodeURIComponent(str)
    .replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
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
  // tri alphabétique par clé, encodage RFC3986 des clefs et valeurs
  const pairs = buildPairsFrom(paramsObj);
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  return pairs.map(([k, v]) => `${encodeRFC3986(k)}=${encodeRFC3986(v)}`).join("&");
}

function canonical_sorted_raw(paramsObj) {
  // tri alphabétique, sans encodage additionnel (URLSearchParams.toString donne encodé léger)
  const pairs = buildPairsFrom(paramsObj);
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

function canonical_raw(paramsObj) {
  // reconstruction naive via URLSearchParams.toString() (ordre d'arrivée)
  return paramsObj.toString();
}

export function verifyProxySignature(req) {
  try {
    const secret = process.env.APP_PROXY_SECRET || "";
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

    // remove hmac for canonicalization
    params.delete("hmac");

    // Useful info for logs
    const shop = params.get("shop") || "";
    const timestamp = params.get("timestamp") || "";
    const digest8_from_request = (hmac || "").slice(0,8);

    // Candidate strings to try
    const candidates = [];

    // --- 1) query-only variants ---
    candidates.push({ label: "rawQuery", str: canonical_raw(params) });
    candidates.push({ label: "sortedRawQuery", str: canonical_sorted_raw(params) });
    candidates.push({ label: "sortedEncodedQuery", str: canonical_sorted_encoded(params) });

    // --- 2) include path variants (Shopify sometimes signs path+query) ---
    // Express path: req.path or req.baseUrl + req.path
    const expressPath = (req.path || req.url?.split("?")[0] || "/").toString();
    const proxyPath = (req.proxyPath || ""); // if you set it on req earlier
    const pathCandidates = [
      { label: "path+rawQuery", prefix: expressPath, body: canonical_raw(params) },
      { label: "path+sortedRawQuery", prefix: expressPath, body: canonical_sorted_raw(params) },
      { label: "path+sortedEncodedQuery", prefix: expressPath, body: canonical_sorted_encoded(params) },
      // proxyPath as given by Shopify (apps/... subpath)
      { label: "proxyPath+rawQuery", prefix: proxyPath || expressPath, body: canonical_raw(params) },
      { label: "proxyPath+sortedRawQuery", prefix: proxyPath || expressPath, body: canonical_sorted_raw(params) },
      { label: "proxyPath+sortedEncodedQuery", prefix: proxyPath || expressPath, body: canonical_sorted_encoded(params) },
    ];
    for (const c of pathCandidates) {
      const prefix = c.prefix || "";
      // ensure slash normalization
      const p = prefix.endsWith("/") ? prefix.slice(0,-1) : prefix;
      const b = c.body ? (c.body.length ? `${p}?${c.body}` : `${p}`) : `${p}`;
      candidates.push({ label: c.label, str: b });
    }

    // --- 3) also try raw "original query string" as received (preserves original ordering & encoding) ---
    if (queryString) candidates.push({ label: "originalRawQS", str: queryString });

    // Now test each candidate
    for (const c of candidates) {
      const digest = toHexDigest(secret, c.str);
      const ok = safeTimingEq(digest, hmac);
      // Log summary small: label, first 8 chars of digest, prov8 (first 8 of computed), ok
      console.log(`[Proxy HMAC] try=${c.label} | base="${c.str.length>120?c.str.slice(0,120)+"...":c.str}" | digest8=${digest.slice(0,8)} | req8=${digest8_from_request} | ok=${ok}`);
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
