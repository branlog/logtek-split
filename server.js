// server.js — Logtek Split (Express + Shopify Proxy) — Compatible Render/Node 18+
// ----------------------------------------------------------
import express from "express";
import fetch from "node-fetch";           // Requêtes HTTP côté Node
import crypto from "crypto";              // HMAC vérification App Proxy

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---- ENV --------------------------------------------------
const SHOP = process.env.SHOPIFY_SHOP_DOMAIN;           // ex: logtek-ci.myshopify.com
const ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;    // Admin API token (app custom)
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN; // Storefront token
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET;  // Shared secret App Proxy
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";   // (optionnel)
const FROM_EMAIL = process.env.FROM_EMAIL || "no-reply@logtek.ca"; // (optionnel)
const PORT = process.env.PORT || 10000;

if (!SHOP || !ADMIN_TOKEN) {
  console.warn("[WARN] SHOPIFY_SHOP_DOMAIN ou SHOPIFY_ADMIN_TOKEN manquant(s).");
}

// ---- Fournisseurs (simple table au départ) ----------------
const VENDORS = [
  { vendor_id: "centre-routier",  name: "Le Centre Routier",  po_email: "commandes@centreroutier.ca" },
  { vendor_id: "carrefour-camion",name: "Carrefour du Camion",po_email: "achat@carrefourcamion.ca" },
  { vendor_id: "flextral",        name: "Hose Flextral",      po_email: "orders@flextral.ca" }
];

// ---- Utils ------------------------------------------------
const escapeHtml = (s) =>
  (s || "").toString().replace(/[&<>"']/g, (m) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[m]));

function verifyProxyHmac(queryString) {
  try {
    const params = new URLSearchParams(queryString || "");
    const hmac = params.get("hmac");
    params.delete("hmac");
    const raw = params.toString();
    const digest = crypto.createHmac("sha256", APP_PROXY_SECRET).update(raw).digest("hex");
    return (
      hmac &&
      crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(hmac, "utf8"))
    );
  } catch {
    return false;
  }
}

async function adminGraphQL(query, variables) {
  const r = await fetch(`https://${SHOP}/admin/api/2025-01/graphql.json`, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": ADMIN_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables })
  });
  return r.json();
}

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
    out.set(pid, {
      account_eligible: n?.m1?.value || "false",
      vendor_id: n?.m2?.value || null
    });
  }
  return out;
}

async function fetchCustomerVendorAccounts(customerId) {
  if (!customerId) return [];
  const gid = `gid://shopify/Customer/${customerId}`;
  const query = `
    query($id:ID!){
      customer(id:$id){
        id
        v: metafield(namespace:"logtek", key:"vendor_accounts"){ value }
      }
    }`;
  const r = await adminGraphQL(query, { id: gid });
  const raw = r?.data?.customer?.v?.value || "[]";
  try { return JSON.parse(raw); } catch { return []; }
}

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

async function createDraftOrderOnAccount(group, customerId) {
  const line_items = group.lines.map((l) => ({
    variant_id: l.variantId,
    quantity: l.quantity
  }));
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
    headers: {
      "X-Shopify-Access-Token": ADMIN_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  }).then((x) => x.json());
  return resp?.draft_order || null;
}

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
    headers: {
      "X-Shopify-Storefront-Access-Token": STOREFRONT_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables })
  }).then((x) => x.json());
  if (r?.data?.checkoutCreate?.userErrors?.length) {
    console.error("Storefront checkoutCreate errors:", r.data.checkoutCreate.userErrors);
  }
  return r?.data?.checkoutCreate?.checkout?.webUrl || null;
}

function buildPOHtml({ vendor, account, draftOrder }) {
  const rows = (draftOrder?.line_items || []).map((li) => {
    const sku = li?.sku || li?.variant_id || "";
    const title = li?.title || "";
    const qty = li?.quantity || 1;
    const total = li?.original_total || "";
    return `<tr><td>${escapeHtml(sku)}</td><td>${escapeHtml(title)}</td><td>${qty}</td><td class="right">${escapeHtml(total?.toString()||"")}</td></tr>`;
  }).join("\n");

  return `<!doctype html><html><head><meta charset="utf-8">
  <style>
    body{font-family:system-ui,Arial,sans-serif;color:#111}
    .head{border-bottom:2px solid #c00;padding:8px 0;margin-bottom:12px}
    .muted{color:#666;font-size:12px}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{border-bottom:1px solid #eee;padding:8px;text-align:left}
    th{background:#fafafa}
    .right{text-align:right}
  </style></head><body>
  <div class="head">
    <h2>LOGTEK — Bon de commande (PO)</h2>
    <div class="muted">PO #: ${escapeHtml(draftOrder?.name||"")} • Date: ${new Date().toLocaleDateString("fr-CA")}</div>
  </div>
  <p><b>Fournisseur:</b> ${escapeHtml(vendor?.name||"")} &nbsp;•&nbsp; <b>No compte:</b> ${escapeHtml(account?.account_no||"")}</p>
  <table>
    <thead><tr><th>SKU</th><th>Description</th><th>Qté</th><th class="right">Total</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p class="muted">Conditions: Facturation au compte selon vos termes. Merci d’accuser réception.</p>
  </body></html>`;
}

async function sendEmail({ to, subject, html }) {
  if (!to || !SENDGRID_API_KEY) return; // Pas de clé = on n'envoie pas (safe)
  const r = await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SENDGRID_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: FROM_EMAIL, name: "LOGTEK" },
      subject,
      content: [{ type: "text/html", value: html }]
    })
  });
  if (!r.ok) console.error("Sendgrid error", await r.text());
}

// ---- Routes -----------------------------------------------

// Healthcheck Render
app.get("/health", (_req, res) => res.status(200).send("ok"));

// App Proxy target: Shopify appellera /apps/logtek-split/prepare => proxifié ici en /prepare?...&hmac=...
app.post("/prepare", async (req, res) => {
  try {
    // Vérif de la signature proxy
    const query = (req.originalUrl.split("?")[1]) || "";
    if (!verifyProxyHmac(query)) {
      return res.status(401).json({ error: "Invalid proxy signature" });
    }

    const { customerId, items } = req.body || {};
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Panier vide" });
    }

    // 1) Metafields produits
    const productIds = [...new Set(items.map((i) => i.product_id))];
    const metas = await fetchProductsMetafields(productIds);

    // 2) Comptes fournisseurs du client
    const accounts = await fetchCustomerVendorAccounts(customerId);
    const mapAcc = new Map(accounts.map((a) => [a.vendor_id, a]));

    // 3) Enrichir lignes
    const enrich = items.map((i) => {
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

    // 5) Créer Draft Orders + PO
    const onAccountSummary = [];
    for (const grp of onAccountGroups) {
      const draft = await createDraftOrderOnAccount(grp, customerId);
      const vendor = VENDORS.find((v) => v.vendor_id === grp.vendorId);
      const poHtml = buildPOHtml({ vendor, account: grp.account, draftOrder: draft });
      // Email fournisseur (si clé présente)
      if (vendor?.po_email && SENDGRID_API_KEY) {
        await sendEmail({ to: vendor.po_email, subject: `LOGTEK PO ${draft?.name || ""}`, html: poHtml });
      }
      onAccountSummary.push({
        vendor_id: grp.vendorId,
        draft_order_id: draft?.id,
        po_number: draft?.name || "",
        total: draft?.total_price || ""
      });
    }

    // 6) Checkout pour la partie à payer maintenant
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

// ---- Start ------------------------------------------------
app.listen(PORT, () => {
  console.log(`Logtek split server on :${PORT}`);
});
