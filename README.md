# SARKAR Restaurant Production V4

Production foundation based on the supplied Customer/Admin HTML files.

## V4 additions
- PostgreSQL-backed orders/settings/menu/admin authentication
- Customer phone OTP verification adapter (enable with OTP_REQUIRED=true and configure OTP_WEBHOOK_URL)
- Razorpay Standard Checkout server-side order creation and signature verification (configure RAZORPAY_KEY_ID/SECRET)
- Payment fields and payment records in PostgreSQL
- Generic order/payment notification webhook adapter
- Admin delivery-link generation and delivery tracking flow
- Customer order tracking and online/COD payment choice

## Important
Real SMS/WhatsApp delivery requires a configured provider webhook. Real payments require Razorpay test/live credentials. Do not put secrets in HTML; keep them in server environment variables.

Razorpay Standard Checkout requires a server-created order and server-side signature verification before treating a payment as genuine. See the official documentation: https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/integration-steps/


## V5 production hardening
- OTP request and order APIs are rate-limited.
- OTP verification locks after 5 failed attempts.
- Razorpay webhook signature verification is included; configure `RAZORPAY_WEBHOOK_SECRET`.
- Payment webhook updates payment/order status from provider events.
- Admin can query delivery sessions for an order.

Before live launch: configure HTTPS, PostgreSQL backups, `JWT_SECRET`, OTP provider, Razorpay live keys/webhook secret, notification provider, and a real deployment domain. Run an end-to-end test in Razorpay test mode first.
