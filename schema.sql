CREATE TABLE IF NOT EXISTS app_users (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  display_name text NOT NULL,
  role text NOT NULL,
  photo text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE app_users DROP CONSTRAINT IF EXISTS app_users_role_check;
UPDATE app_users SET role = 'cashier' WHERE role = 'user';
ALTER TABLE app_users
  ADD CONSTRAINT app_users_role_check
  CHECK (role IN ('admin', 'supervisor', 'cashier', 'inventory'));

CREATE TABLE IF NOT EXISTS app_sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS app_sessions_expires_at_idx ON app_sessions (expires_at);

CREATE TABLE IF NOT EXISTS business_state (
  id smallint PRIMARY KEY CHECK (id = 1),
  version bigint NOT NULL DEFAULT 0,
  imported_at timestamptz,
  data jsonb NOT NULL DEFAULT '{"services":[],"clients":[],"payments":[],"monthlyCharges":[],"companyProfile":{"name":"Mi empresa","address":"","phone":"","logo":""}}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE business_state ADD COLUMN IF NOT EXISTS imported_at timestamptz;

INSERT INTO business_state (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;
