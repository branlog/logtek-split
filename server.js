// server.js — Express sur Render (Logtek Split)
import express from 'express';
import crypto from 'crypto';

const app = express();

// Shopify envoie les requêtes App Proxy en x-www-form-urlencoded (GET) ou JSON (via fetch côté vitrine).
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----------- ENV -----------
const SHOP = process.env.SHOPIFY_SHOP_DOMAIN; // ex: logtek-ci.myshopify.com
const ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN;
const APP_PROXY_SECRET = process.env.APP_PROXY_SECRET;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'no-reply@logtek.ca';

if (!SHOP || !ADMIN_TOKEN) {
  console.warn('[WARN] SHOPIFY_SHOP_DOMAIN or SHOPIFY_ADMIN_TOKEN is missing. Set them in Render > Environment.');
}

// ----------- Fournisseurs -----------
const VENDORS = [
  { vendor_id: 'centre-routier', name: 'Le Centre Routier', po_email: 'commandes@centreroutier.ca' },
  { vendor_id: 'carrefour-camion', name: 'Carrefour du Camion', po_email: 'achat@carrefourcamion.ca' },
  { vendor_id: 'flextral',_
