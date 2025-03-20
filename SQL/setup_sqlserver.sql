CREATE DATABASE IF NOT EXISTS password_manager;
GO

USE password_manager;
GO

CREATE TABLE IF NOT EXISTS user (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL
);
GO

CREATE INDEX idx_username ON user (username);
GO

CREATE TABLE IF NOT EXISTS password (
    id INT IDENTITY(1,1) PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    notes VARCHAR(500) NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
);
GO

CREATE INDEX idx_user_id ON password (user_id);
GO

CREATE TABLE IF NOT EXISTS audit_log (
    id INT IDENTITY(1,1) PRIMARY KEY,
    event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_message TEXT,
    event_type VARCHAR(255),
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
);
GO

CREATE INDEX idx_event_type_user_id ON audit_log (event_type, user_id);
GO

CREATE INDEX idx_event_time ON audit_log (event_time);
GO

INSERT INTO user (username, password, role)
SELECT 'ADMIN', '$scrypt$ln=16,r=8,p=1$DaE0phQiJOTcuxeCsFaq1Q$1MZ0Uk7thd31SuJEHwZvbdMkr3pmbKmAuoyd1SQRSls', 'admin'
WHERE NOT EXISTS (SELECT 1 FROM user WHERE username = 'ADMIN');
GO
