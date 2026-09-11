# ZhuoMarket Backend v2.0.0

Backend Node.js + Express + PostgreSQL prepared to match the ZhuoMarket frontend API contract.

## Render
1. Create a PostgreSQL database on Render.
2. Deploy this folder as a Web Service.
3. Build: `npm install`
4. Start: `npm start`
5. Set `DATABASE_URL`, `JWT_SECRET`, `OWNER_EMAIL`, `OWNER_PASSWORD`.
6. Optional: `ADMIN_WHATSAPP`, `PUSH_PUBLIC_KEY`, Stripe/PayPal secrets.
7. Health check: `/api/health`

## Important payment rule
Manual payments are REAL manual verification. Submitting a transaction reference creates a `pending` payment. It does NOT mark the order paid. Only an admin approval endpoint changes the payment to `paid`.

## Owner protection
The account defined by `OWNER_EMAIL` is created/promoted to `owner`. The owner cannot be removed or demoted through the admin user endpoint.

## Frontend target
Set the frontend API base to:
`https://backend-zhuo.onrender.com`

This backend includes compatibility aliases for the frontend's manual payment route and several older API shapes to reduce future route mismatch problems.
