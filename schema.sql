CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL, password_hash text NOT NULL, name text,
 avatar text, role text NOT NULL DEFAULT 'client' CHECK(role IN ('client','admin','owner')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS products (
 id uuid PRIMARY KEY, name text NOT NULL, brand text DEFAULT '', category text DEFAULT 'Téléphone',
 price numeric(12,2) NOT NULL DEFAULT 0, currency text NOT NULL DEFAULT 'USD', stock integer NOT NULL DEFAULT 0,
 image text DEFAULT '', description text DEFAULT '', storage text DEFAULT '', active boolean NOT NULL DEFAULT true,
 seller_id uuid REFERENCES users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS promotions (
 id uuid PRIMARY KEY, title text DEFAULT '', image text DEFAULT '', description text DEFAULT '', active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payment_methods (
 id uuid PRIMARY KEY, provider text NOT NULL, description text DEFAULT '', instructions text DEFAULT '', transfer_number text DEFAULT '',
 account_number text DEFAULT '', active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
 id uuid PRIMARY KEY, customer_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT, items jsonb NOT NULL,
 total numeric(12,2) NOT NULL, currency text NOT NULL DEFAULT 'USD', payment_method text, payment_status text NOT NULL DEFAULT 'pending'
 CHECK(payment_status IN ('pending','paid','rejected','cancelled')), status text NOT NULL DEFAULT 'En attente', delivery_done boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payments (
 id uuid PRIMARY KEY, order_id uuid NOT NULL REFERENCES orders(id) ON DELETE RESTRICT, customer_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 payment_method text NOT NULL, amount numeric(12,2) NOT NULL, currency text NOT NULL DEFAULT 'USD', transaction_reference text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','rejected','cancelled')), rejection_reason text,
 created_at timestamptz NOT NULL DEFAULT now(), verified_at timestamptz, verified_by uuid REFERENCES users(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS payments_reference_unique ON payments(lower(transaction_reference));
CREATE UNIQUE INDEX IF NOT EXISTS payments_one_active_per_order ON payments(order_id) WHERE status IN ('pending','paid');
CREATE TABLE IF NOT EXISTS user_state (user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, cart jsonb NOT NULL DEFAULT '[]', wishlist jsonb NOT NULL DEFAULT '[]', updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS notifications (id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE CASCADE, title text DEFAULT '', body text DEFAULT '', read boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS messages (id uuid PRIMARY KEY, sender_id uuid REFERENCES users(id) ON DELETE SET NULL, receiver_id uuid REFERENCES users(id) ON DELETE SET NULL, body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), read boolean NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS trades (id uuid PRIMARY KEY, user_id uuid REFERENCES users(id) ON DELETE SET NULL, product_id uuid REFERENCES products(id) ON DELETE SET NULL, message text DEFAULT '', status text NOT NULL DEFAULT 'pending', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS push_subscriptions (id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, subscription jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(user_id));
CREATE TABLE IF NOT EXISTS app_settings (key text PRIMARY KEY, value jsonb NOT NULL DEFAULT '{}', updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS streaming_orders (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT, service text NOT NULL CHECK(service IN ('netflix','disney')),
 plan_id text DEFAULT '', plan_name text DEFAULT '', price numeric(12,2) NOT NULL DEFAULT 0, currency text NOT NULL DEFAULT 'USD',
 customer jsonb NOT NULL DEFAULT '{}', payment_status text NOT NULL DEFAULT 'pending' CHECK(payment_status IN ('pending','paid','rejected','cancelled')),
 status text NOT NULL DEFAULT 'Nouvelle demande', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 verified_at timestamptz, verified_by uuid REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS streaming_orders_user_created_idx ON streaming_orders(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS streaming_orders_status_created_idx ON streaming_orders(payment_status,created_at DESC);
CREATE INDEX IF NOT EXISTS products_active_created_idx ON products(active,created_at DESC);
CREATE INDEX IF NOT EXISTS orders_customer_created_idx ON orders(customer_id,created_at DESC);
CREATE INDEX IF NOT EXISTS payments_status_created_idx ON payments(status,created_at DESC);
CREATE INDEX IF NOT EXISTS messages_receiver_read_idx ON messages(receiver_id,read,created_at DESC);
