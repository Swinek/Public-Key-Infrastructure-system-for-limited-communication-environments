CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,

    serial_number VARCHAR(100) UNIQUE NOT NULL,

    certificate_pem TEXT,
    fingerprint VARCHAR(128),

    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,

    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',

    issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ NULL,
    revocation_reason VARCHAR(255) NULL
);

-- Certyfikaty Root CA (DER). Najnowszy wiersz = bieżące CA; poprzednie zostają do wglądu.
CREATE TABLE IF NOT EXISTS ca_certificates (
    id SERIAL PRIMARY KEY,
    fingerprint VARCHAR(64) UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    certificate_der BYTEA NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Podpisane CRL (DER). crl_number = CRLNumber (RFC 5280 §5.2.3), rośnie przy każdej nowej liście.
-- trigger: startup | new_ca | revocation | scheduled | manual
CREATE TABLE IF NOT EXISTS crls (
    crl_number BIGINT PRIMARY KEY,
    ca_fingerprint VARCHAR(64) NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    revoked_count INT NOT NULL,
    crl_der BYTEA NOT NULL,
    trigger VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Konto portalu klienta: tylko odczyt (portal nie podpisuje i nie zmienia danych PKI).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pki_portal') THEN
        CREATE ROLE pki_portal LOGIN PASSWORD 'pki_portal_password';
    END IF;
END
$$;
ALTER ROLE pki_portal SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE pki_db TO pki_portal;
GRANT USAGE ON SCHEMA public TO pki_portal;
GRANT SELECT ON users, certificates, ca_certificates, crls TO pki_portal;

-- Initial seed data
INSERT INTO users (username, email, role) VALUES
('john_doe', 'john.doe@pki.local', 'user'),
('jane_smith', 'jane.smith@pki.local', 'user'),
('admin', 'admin@pki.local', 'admin')
ON CONFLICT DO NOTHING;
