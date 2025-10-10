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
function verifyProxySignature(req) {
  try {
    const secret = process.env.APP_PROXY_SECRET;
    const url = new URL(req.originalUrl, `https://${req.headers.host}`);

    // Étape 1 — récupérer les paramètres
    const params = new URLSearchParams(url.search);
    const hmac = params.get("signature") || params.get("hmac");
    if (!hmac) return false;
    params.delete("signature");
    params.delete("hmac");

    // Étape 2 — trier les paires alphabétiquement
    const sorted = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");

    // Étape 3 — générer la signature selon Shopify
    const computed = crypto
      .createHmac("sha256", secret)
      .update(sorted)
      .digest("hex");

    // Étape 4 — comparaison sécurisée
    const ok = crypto.timingSafeEqual(
      Buffer.from(computed, "utf8"),
      Buffer.from(hmac, "utf8")
    );

    console.log("[Proxy HMAC]", { sorted, computed, hmac, ok });
    return ok;
  } catch (err) {
    console.error("Proxy verification failed:", err);
    return false;
  }
}


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
