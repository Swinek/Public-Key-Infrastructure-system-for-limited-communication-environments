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
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, REVOKED
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    revocation_reason VARCHAR(255) NULL
);

-- Initial seed data
INSERT INTO users (username, email, role) VALUES
('john_doe', 'john.doe@pki.local', 'user'),
('jane_smith', 'jane.smith@pki.local', 'user'),
('admin', 'admin@pki.local', 'admin')
ON CONFLICT DO NOTHING;

INSERT INTO certificates (user_id, serial_number, status) VALUES
(1, 'SN-8374920173', 'ACTIVE'),
(2, 'SN-1928475630', 'REVOKED')
ON CONFLICT DO NOTHING;
