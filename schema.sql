CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id=1),
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  en TEXT DEFAULT '',
  price NUMERIC(12,2) NOT NULL CHECK (price>=0),
  description TEXT DEFAULT '',
  image TEXT DEFAULT '',
  video TEXT DEFAULT '',
  published BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  items JSONB NOT NULL,
  subtotal NUMERIC(12,2) NOT NULL CHECK (subtotal>=0),
  delivery_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (delivery_fee>=0),
  total NUMERIC(12,2) NOT NULL CHECK (total>=0),
  status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW','ACCEPTED','PREPARING','READY','OUT_FOR_DELIVERY','DELIVERED','CANCELLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  access_token_hash TEXT,
  payment_method TEXT NOT NULL DEFAULT 'COD' CHECK (payment_method IN ('COD','ONLINE')),
  payment_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (payment_status IN ('PENDING','PAID','FAILED','REFUNDED'))
);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT NOT NULL DEFAULT 'COD';
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT NOT NULL DEFAULT 'PENDING';
CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_order_id TEXT UNIQUE,
  provider_payment_id TEXT,
  amount BIGINT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'INR',
  status TEXT NOT NULL,
  signature TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS payments_order_idx ON payments(order_id);

CREATE INDEX IF NOT EXISTS orders_phone_idx ON orders(phone);
CREATE INDEX IF NOT EXISTS orders_created_idx ON orders(created_at DESC);
INSERT INTO settings(id,data) VALUES(1,'{}') ON CONFLICT (id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS orders_access_token_hash_idx ON orders(access_token_hash) WHERE access_token_hash IS NOT NULL;
CREATE TABLE IF NOT EXISTS delivery_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '24 hours')
);
CREATE TABLE IF NOT EXISTS tracking_points (
  id BIGSERIAL PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  latitude DOUBLE PRECISION NOT NULL CHECK(latitude BETWEEN -90 AND 90),
  longitude DOUBLE PRECISION NOT NULL CHECK(longitude BETWEEN -180 AND 180),
  accuracy DOUBLE PRECISION,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tracking_points_order_time_idx ON tracking_points(order_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS customer_otps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS customer_otps_phone_idx ON customer_otps(phone, created_at DESC);
