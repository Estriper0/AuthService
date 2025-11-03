CREATE TABLE IF NOT EXISTS users (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email varchar(50) UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_email ON users (email);

CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL UNIQUE
);

INSERT INTO apps (id, name, secret) VALUES (1, 'event_hub', 'secret_key');