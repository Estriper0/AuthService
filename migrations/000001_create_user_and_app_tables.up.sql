CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE IF NOT EXISTS auth.users (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email varchar(50) UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_email ON auth.users (email);