import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ENV
const SHOP             = process.env.SHOPIFY_SHOP_DOMAIN;      // ex: 2uvcbu-ci.myshopify.com
const ADMIN_TOKEN      = process.env.SHOPIFY_ADMIN_TOKEN;
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN;
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET;         // Partner Dashboard → Settings → Secret
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";
const FROM_EMAIL       = process.env.FROM_EMAIL || "no-reply@logtek.ca";
const PORT             = process.env.PORT || 10000;

// --- Utils
const escapeHtml = s => (s||"").toString().replace(/[&<>"']/g, m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));

// =============== HMAC (App Proxy) =================
// Shopify peut envoyer `hmac` (nouveau) ou `signature` (ancien).
// Certains thèmes/instances signent `path?query` au lieu de la query seule.
// On vérifie proprement et on logge.
function safeHmacEq(a, b) {
  try { return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")); }
  catch { return false; }
}

function canonicalize(paramsObj) {
  const pairs = [];
  for (const [k, v] of paramsObj.entries()) pairs.push([k, v]);
  pairs.sort((a,b)=>a[0].localeCompare(b[0]));
  return pairs.map(([k,v])=>`${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

function verifyProxySignature(req) {
  const full = req.originalUrl || "";
  const qStr = full.includes("?") ? full.split("?")[1] : "";
  const qp   = new URLSearchParams(qStr);

  // récupérer signature (hmac prioritaire)
  const hmacParam = qp.get("hmac");
  const sigParam  = qp.get("signature"); // fallback legacy
  const provided  = hmacParam || sigParam;
  if (!provided) {
    console.log("[Proxy] aucun hmac/signature dans la query");
    return false;
  }

  // retirer les clés de signature
  qp.delete("hmac"); qp.delete("signature");

  // variantes possibles
  const canonicalQ = canonicalize(qp);
  const pathOnly   = req.path || req.url.split("?")[0] || "/prepare"; // ex: /prepare
  const withPath   = canonicalQ ? `${pathOnly}?${canonicalQ}` : pathOnly;

  const variants = [
    { label: "query",      data: canonicalQ },
    { label: "path+query", data: withPath  },
  ];

  for (const v of variants) {
    const digest = crypto.createHmac("sha256", APP_PROXY_SECRET).update(v.data).digest("hex");
    const ok = safeHmacEq(digest, provided);
    console.log(`[Proxy HMAC] try=${v.label} | digest8=${digest.slice(0,8)} | prov8=${provided.slice(0,8)} | ok=${ok}`);
    if (ok) return true;
  }
  return false;
}
// ===================================================

// --- Shopify Admin GraphQL helper
async function adminGraphQL(query, variables) {
  const r = await fetch(`https://${SHOP}/admin/api/2025-01/graphql.json`, {
    method: "POST",
    headers: { "X-Shopify-Access-Token": ADMIN_TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  return r.json();
}

// --- Metafields produits
async function fetchProductsMetafields(productIds) {
  if (!productIds?.length) return new Map();
  const ids = productIds.map(id=>`gid://shopify/Product/${id}`);
  const q = `
    query($ids:[ID!]!){
      nodes(ids:$ids){
        ... on Product {
          id
          m1: metafield(namespace:"logtek", key:"account_eligible"){ value }
          m2: metafield(namespace:"logtek", key:"vendor_id"){ value }
        }
      }
    }`;
  const r = await adminGraphQL(q, { ids });
  const out = new Map();
  for (const n of r?.data?.nodes || []) {
    if (!n) continue;
    const pid = Number(n.id.split("/").pop());
    out.set(pid, { account_eligible: n?.m1?.value || "false", vendor_id: n?.m2?.value || null });
  }
  return out;
}

// --- Comptes fournisseurs client
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
  try { return JSON.parse(r?.data?.customer?.v?.value || "[]"); } catch { return []; }
}

// --- Split
function splitByVendorAndTerms(lines, vendorMap) {
  const groups = new Map(); const payNow = [];
  for (const l of lines) {
    const hasAccount = l.vendorId && vendorMap.has(l.vendorId);
    const canAccount = hasAccount && l.accountEligible;
    if (canAccount) { if (!groups.has(l.vendorId)) groups.set(l.vendorId, []); groups.get(l.vendorId).push(l); }
    else payNow.push(l);
  }
  const onAccountGroups = Array.from(groups.entries()).map(([vendorId, lines]) => ({
    vendorId, lines, account: vendorMap.get(vendorId) || null
  }));
  return { onAccountGroups, payNowLines: payNow };
}

// --- Draft order au compte
async function createDraftOrderOnAccount(group, customerId) {
  const line_items = group.lines.map(l=>({ variant_id: l.variantId, quantity: l.quantity }));
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
  }).then(x=>x.json());
  return resp?.draft_order || null;
}

// --- Checkout pay-now (Storefront)
async function createPayNowCheckout(payNowLines) {
  const lineItems = payNowLines.map(l=>({ quantity: l.quantity, variantId: `gid://shopify/ProductVariant/${l.variantId}` }));
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
  }).then(x=>x.json());
  return r?.data?.checkoutCreate?.checkout?.webUrl || null;
}

// --- Health
app.get("/health", (_req,res)=>res.status(200).send("ok"));

// --- GET /prepare (test navigateur)
app.get("/prepare", (req,res)=>{
  if (!verifyProxySignature(req)) return res.status(401).json({ error: "Invalid proxy signature" });
  return res.status(200).json({ error: "Panier vide" });
});

// --- POST /prepare (prod)
app.post("/prepare", async (req,res)=>{
  try {
    if (!verifyProxySignature(req)) return res.status(401).json({ error: "Invalid proxy signature" });

    const { customerId, items } = req.body || {};
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Panier vide" });
    }

    const productIds = [...new Set(items.map(i=>i.product_id))];
    const metas = await fetchProductsMetafields(productIds);
    const accounts = await fetchCustomerVendorAccounts(customerId);
    const mapAcc = new Map(accounts.map(a=>[a.vendor_id, a]));

    const enrich = items.map(i=>{
      const m = metas.get(i.product_id) || {};
      return {
        productId: i.product_id,
        variantId: i.variant_id,
        quantity: i.quantity,
        accountEligible: m.account_eligible === "true" || m.account_eligible === true,
        vendorId: m.vendor_id || null
      };
    });

    const { onAccountGroups, payNowLines } = splitByVendorAndTerms(enrich, mapAcc);

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

app.listen(PORT, ()=>console.log(`Logtek split server on :${PORT}`));

