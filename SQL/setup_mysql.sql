CREATE DATABASE IF NOT EXISTS password_manager;

USE password_manager;

CREATE TABLE IF NOT EXISTS user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    failed_login_attempts INT NOT NULL,
    INDEX idx_username (username),
    INDEX idx_failed_logins (failed_login_attempts)
);

CREATE TABLE IF NOT EXISTS password (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    notes VARCHAR(500) NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id),
    INDEX idx_user_id (user_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_message TEXT,
    event_type VARCHAR(255),
    user_id INT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE SET NULL,
    INDEX idx_event_type_user_id (event_type, user_id),
    INDEX idx_event_time (event_time)
);

CREATE TABLE token_blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    jti VARCHAR(36) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_jti (jti)
);

INSERT INTO user (username, password, role, failed_login_attempts)
SELECT 'ADMIN', '$scrypt$ln=16,r=8,p=1$DaE0phQiJOTcuxeCsFaq1Q$1MZ0Uk7thd31SuJEHwZvbdMkr3pmbKmAuoyd1SQRSls', 'admin', 0
WHERE NOT EXISTS (SELECT 1 FROM user WHERE username = 'ADMIN');
