// ============================================================================
// Logtek Split (Shopify App Proxy + Render) — Version complète tout-en-un
// ============================================================================

import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
const PORT = process.env.PORT || 10000;
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;
const FROM_EMAIL = process.env.FROM_EMAIL || "info@logtek.ca";

if (!APP_PROXY_SECRET || !SHOPIFY_ADMIN_TOKEN || !SHOPIFY_SHOP_DOMAIN) {
  console.error("❌ Configuration manquante dans les variables d'environnement.");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const short = (s = "") => (s ? String(s).slice(0, 8) : "");

function verifyProxySignature(req) {
  try {
    const original = req.originalUrl || req.url || "";
    const pathOnly = original.split("?")[0] || req.path || "/prepare";
    const qs = original.includes("?") ? original.split("?")[1] : "";
    const params = new URLSearchParams(qs);
    const providedHmac = params.get("hmac");
    const providedSig = params.get("signature");
    const provided = providedHmac || providedSig;
    if (!provided) return false;
    params.delete("hmac"); params.delete("signature");
    const sortedQ = new URLSearchParams(
      Array.from(params.entries()).sort((a, b) => a[0].localeCompare(b[0]))
    ).toString();
    const expressPath = req.path || pathOnly;
    const proxyPath = `/apps/logtek-split${expressPath}`;
    const proxyRoot = `/apps/logtek-split`;
    const candidates = [
      sortedQ ? `${expressPath}?${sortedQ}` : expressPath,
      sortedQ ? `${proxyPath}?${sortedQ}` : proxyPath,
      sortedQ ? `${proxyRoot}?${sortedQ}` : proxyRoot
    ];
    for (const base of candidates) {
      const digest = crypto.createHmac("sha256", APP_PROXY_SECRET).update(base).digest("hex");
      const ok = crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(provided, "utf8"));
      console.log(`[Proxy HMAC] base="${base}" | d8=${short(digest)} | p8=${short(provided)} | ok=${ok}`);
      if (ok) return true;
    }
    console.log("[Proxy] aucune variante ne matche → 401");
    return false;
  } catch (e) {
    console.log("[Proxy] exception verify:", e?.message || e);
    return false;
  }
}

async function adminGraphQL(query, variables = {}) {
  const url = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables })
  });
  if (!res.ok) throw new Error(`[adminGraphQL] ${res.status}`);
  const json = await res.json();
  if (json.errors) throw new Error(JSON.stringify(json.errors));
  return json.data;
}

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
    return JSON.parse(data?.customer?.vendor?.value || "[]");
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
  if (errs && errs.length) throw new Error(JSON.stringify(errs));
  return data?.draftOrderCreate?.draftOrder;
}

function splitByVendorAndTerms(lines = [], vendorMap = {}) {
  const groups = new Map();
  const payNow = [];
  for (const l of lines) {
    const vendor = l.vendor || "unknown";
    const eligible = vendorMap[vendor]?.eligible ?? false;
    if (eligible) {
      if (!groups.has(vendor)) groups.set(vendor, []);
      groups.get(vendor).push(l);
    } else payNow.push(l);
  }
  return { groups, payNow };
}

function toDraftOrderLine(l) {
  const line = { title: l.title, quantity: l.quantity || 1 };
  if (l.variantId) line.variantId = l.variantId;
  return line;
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/prepare", (req, res) => {
  if (!verifyProxySignature(req)) return res.status(403).json({ error: "Invalid proxy signature" });
  return res.json({ error: "Panier vide" });
});

app.post("/prepare", async (req, res) => {
  if (!verifyProxySignature(req)) return res.status(403).json({ error: "Invalid proxy signature" });
  try {
    const { customerId, email, lines = [] } = req.body || {};
    const vendorAccounts = await fetchCustomerVendorAccounts(customerId);
    const vendorMap = {};
    for (const v of vendorAccounts) vendorMap[v.vendor] = { eligible: !!v.eligible };
    const { groups, payNow } = splitByVendorAndTerms(lines, vendorMap);
    const created = [];
    for (const [vendor, glines] of groups.entries()) {
      const lineItems = glines.map(toDraftOrderLine);
      const draft = await createDraftOrder({ email: email || FROM_EMAIL, lineItems, note: `Compte fournisseur: ${vendor}` });
      created.push({ vendor, draftOrderId: draft?.id, invoiceUrl: draft?.invoiceUrl });
    }
    return res.json({ ok: true, vendorOrders: created, payNow });
  } catch (e) {
    console.error("[/prepare] error:", e);
    return res.status(500).json({ error: "internal_error", details: String(e?.message || e) });
  }
});

app.listen(PORT, () => console.log(`✅ Logtek Split prêt sur port ${PORT}`));
