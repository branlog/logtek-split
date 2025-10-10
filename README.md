# Logtek Split (Render + Shopify App Proxy)
Déploiement:
1. Déploie sur Render (Node 18+).
2. Variables d'env:
   - APP_PROXY_SECRET
   - SHOPIFY_ADMIN_TOKEN
   - SHOPIFY_SHOP_DOMAIN
   - PORT=10000
3. Proxy URL Shopify: https://<service>.onrender.com/
4. Test: https://<store>.myshopify.com/apps/logtek-split/prepare
