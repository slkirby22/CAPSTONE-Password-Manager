CREATE DATABASE IF NOT EXISTS password_manager;

USE password_manager;

CREATE TABLE IF NOT EXISTS user(
id INT auto_increment PRIMARY KEY,
username VARCHAR(255) NOT NULL,
password VARCHAR(255) NOT NULL,
role VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS password(
id INT AUTO_INCREMENT PRIMARY KEY,
service_name VARCHAR(255) NOT NULL,
username VARCHAR(255) NOT NULL,
password VARCHAR(255) NOT NULL,
notes VARCHAR(500) NULL,
user_id INT NOT NULL,
FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_message TEXT,
    event_type VARCHAR(255),
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) references user(id)
);

INSERT INTO user (username, password, role)
select 'ADMIN', '$scrypt$ln=16,r=8,p=1$DaE0phQiJOTcuxeCsFaq1Q$1MZ0Uk7thd31SuJEHwZvbdMkr3pmbKmAuoyd1SQRSls', 'admin'
WHERE NOT EXISTS (SELECT 1 FROM user WHERE username = 'ADMIN');