# ZhuoMarket Backend — FINAL MATCHED v3

Backend REST pour le frontend ZhuoMarket QA Improved Final.

## Déploiement Render

1. Crée/actualise le service Web Render avec ce dossier.
2. Ajoute une base PostgreSQL Render et mets `DATABASE_URL`.
3. Mets les variables de `.env.example` dans Render.
4. `npm install` puis `npm start`.
5. Vérifie `/api/health`.

### Variables indispensables
- `DATABASE_URL`
- `JWT_SECRET`
- `FRONTEND_ORIGIN` = domaine Vercel exact du frontend
- `OWNER_EMAIL`
- `OWNER_PASSWORD`
- `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET` pour les photos persistantes

### Paiements
- Manual payments: réels, enregistrés en `pending` avec transaction reference.
- PayPal: réel uniquement si `PAYPAL_CLIENT_ID` + `PAYPAL_CLIENT_SECRET` sont configurés. Le backend crée/capture les orders PayPal; aucun secret n'est exposé au frontend.
- Stripe n'est pas activé dans cette version car le frontend actuel n'appelle pas Stripe directement. Ne pas simuler un paiement.

## Important
Ce backend ne contient aucune donnée produit/publicité de démonstration. Les produits, photos, commandes, utilisateurs, promotions et paiements viennent de PostgreSQL.

Les fichiers uploadés sur Render ne sont pas stockés sur le disque local: Cloudinary est utilisé pour que les photos restent disponibles après redémarrage/redéploiement.
