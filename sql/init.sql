-- Create DB (if you have permission)
CREATE DATABASE fortressauth;

-- Connect to the database
\c fortressauth;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert admin user (replace <BCRYPT_HASH> with hash generated in PHP CLI)
INSERT INTO users (username, password_hash) VALUES ('admin', '<BCRYPT_HASH>');
