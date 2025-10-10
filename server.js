// ============================================================================
// server.js — Logtek Split (Shopify App Proxy + Render) — Node 18+
// Subpath proxy attendu : /apps/logtek-split
// ============================================================================

import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
const PORT = process.env.PORT || 10000;

// --- ENV requis
const APP_PROXY_SECRET     = process.env.APP_PROXY_SECRET;        // Shopify App "Secret"
const SHOPIFY_ADMIN_TOKEN  = process.env.SHOPIFY_ADMIN_TOKEN;     // Admin API token (Private/Custom app)
const SHOPIFY_SHOP_DOMAIN  = process.env.SHOPIFY_SHOP_DOMAIN;     // ex: 2uvcbu-ci.myshopify.com
const FROM_EMAIL           = process.env.FROM_EMAIL || "info@logtek.ca";

// --- Garde-fou
if (!APP_PROXY_SECRET || !SHOPIFY_ADMIN_TOKEN || !SHOPIFY_SHOP_DOMAIN) {
  console.error("❌ ENV manquantes: APP_PROXY_SECRET / SHOPIFY_ADMIN_TOKEN / SHOPIFY_SHOP_DOMAIN");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Petit helper log
const short = (s = "") => (s ? String(s).slice(0, 8) : "");

/**
 * Vérifie la signature proxy Shopify (HMAC SHA256 avec APP_PROXY_SECRET).
 * On teste plusieurs bases possibles (path express, path proxy, racine proxy) + query triée.
 * Renvoie true si une variante matche.
 */
import crypto from "crypto";

/**
 * Vérifie la signature d'un App Proxy Shopify.
 * - Accepte le format "query triée" (ancien)
 * - Accepte le format "path(proxy)?query" (nouveau)
 * - Encodage strict via encodeURIComponent
 */
function verifyProxySignature(req) {
  try {
    const secret = process.env.APP_PROXY_SECRET;
    if (!secret) return false;

    const url = new URL(req.originalUrl, `https://${req.headers.host}`);
    const params = new URLSearchParams(url.search);

    // Shopify peut envoyer 'signature' (proxy) ou 'hmac' (autres flux)
    const sig = params.get("signature") || params.get("hmac");
    if (!sig) return false;
    params.delete("signature");
    params.delete("hmac");

    // 1) Construire la query canoniquement triée + encodée
    const sortedQuery = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    // 2) Essai A : HMAC(query)
    const hA = crypto.createHmac("sha256", secret).update(sortedQuery).digest("hex");
    const okA = safeEq(hA, sig);
    if (okA) {
      console.log("[Proxy HMAC] ok via query", { hA: hA.slice(0, 8) });
      return true;
    }

    // 3) Essai B : HMAC(path(proxy) + '?' + query)
    //    path(proxy) = path_prefix (fourni par Shopify dans la query) + req.path
    const prefix = params.get("path_prefix") || "";
    const proxyPath = `${prefix}${req.path}`; // ex: /apps/logtek-split + /prepare
    const base = sortedQuery ? `${proxyPath}?${sortedQuery}` : proxyPath;

    const hB = crypto.createHmac("sha256", secret).update(base).digest("hex");
    const okB = safeEq(hB, sig);
    console.log("[Proxy HMAC] try A/B", {
      okA,
      okB,
      proxyPath,
      digestA8: hA.slice(0, 8),
      digestB8: hB.slice(0, 8),
      sig8: (sig || "").slice(0, 8),
    });
    return okB;
  } catch (e) {
    console.error("Proxy verification error:", e);
    return false;
  }
}

function safeEq(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch {
    return false;
  }
}

export { verifyProxySignature };


// --------------------- Shopify Admin GraphQL helpers ------------------------

async function adminGraphQL(query, variables = {}) {
  const url = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`[adminGraphQL] ${res.status} ${text}`);
  }
  const json = await res.json();
  if (json.errors) throw new Error(`[adminGraphQL] ${JSON.stringify(json.errors)}`);
  return json.data;
}

// Récupère la liste des comptes fournisseurs autorisés dans un metafield JSON
async function fetchCustomerVendorAccounts(customerId) {
  if (!customerId) return [];
  const gid = `gid://shopify/Customer/${customerId}`;
  const q = `
    query($id: ID!) {
      customer(id: $id) {
        id
        vendor: metafield(namespace: "logtek", key: "vendor_accounts"){ value }
      }
    }
  `;
  try {
    const data = await adminGraphQL(q, { id: gid });
    return JSON.parse(data?.customer?.vendor?.value || "[]"); // ex: [{vendor:"ABC", eligible:true}]
  } catch {
    return [];
  }
}

async function createDraftOrder({ email, lineItems, note }) {
  const q = `
    mutation($i: DraftOrderInput!) {
      draftOrderCreate(input: $i) {
        draftOrder { id invoiceUrl }
        userErrors { field message }
      }
    }
  `;
  const variables = { i: { email, lineItems, note } };
  const data = await adminGraphQL(q, variables);
  const errs = data?.draftOrderCreate?.userErrors;
  if (errs?.length) throw new Error(JSON.stringify(errs));
  return data?.draftOrderCreate?.draftOrder;
}

// --------------------------- Split & mapping helpers ------------------------

function splitByVendorAndTerms(lines = [], vendorMap = {}) {
  const groups = new Map();
  const payNow = [];
  for (const l of lines) {
    const vendor   = l.vendor || "unknown";
    const eligible = vendorMap[vendor]?.eligible ?? false;
    if (eligible) {
      if (!groups.has(vendor)) groups.set(vendor, []);
      groups.get(vendor).push(l);
    } else {
      payNow.push(l);
    }
  }
  return { groups, payNow };
}

function toDraftOrderLine(l) {
  const out = { title: l.title, quantity: l.quantity || 1 };
  if (l.variantId) out.variantId = l.variantId;  // si on a l'ID de variante
  return out;
}

// --------------------------------- Routes -----------------------------------

app.get("/health", (req, res) => res.json({ ok: true }));

// GET /prepare via proxy (retourne un message par défaut si pas de body)
app.get("/prepare", (req, res) => {
  if (!verifyProxySignature(req)) return res.status(403).json({ error: "Invalid proxy signature" });
  return res.json({ error: "Panier vide" });
});

// POST /prepare avec { customerId, email, lines:[{title,quantity,vendor,variantId?}, ...] }
app.post("/prepare", async (req, res) => {
  if (!verifyProxySignature(req)) return res.status(403).json({ error: "Invalid proxy signature" });

  try {
    const { customerId, email, lines = [] } = req.body || {};

    // 1) récup des vendors autorisés pour ce client
    const vendorAccounts = await fetchCustomerVendorAccounts(customerId);
    const vendorMap = {};
    for (const v of vendorAccounts) vendorMap[v.vendor] = { eligible: !!v.eligible };

    // 2) split
    const { groups, payNow } = splitByVendorAndTerms(lines, vendorMap);

    // 3) création de Draft Orders par vendor (au compte)
    const created = [];
    for (const [vendor, glines] of groups.entries()) {
      const lineItems = glines.map(toDraftOrderLine);
      const draft = await createDraftOrder({
        email: email || FROM_EMAIL,
        lineItems,
        note: `Compte fournisseur: ${vendor}`,
      });
      created.push({ vendor, draftOrderId: draft?.id, invoiceUrl: draft?.invoiceUrl });
    }

    return res.json({ ok: true, vendorOrders: created, payNow });
  } catch (e) {
    console.error("[/prepare] error:", e);
    return res.status(500).json({ error: "internal_error", details: String(e?.message || e) });
  }
});

app.listen(PORT, () => console.log(`✅ Logtek Split prêt sur port ${PORT}`));
