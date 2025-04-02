USE [master]
GO

PRINT 'Setting up SQL Server for password manager application...'
GO

-- 1. Enable mixed mode authentication if not already enabled (requires server restart)
DECLARE @reg_value INT
EXEC master.dbo.xp_instance_regread 
    N'HKEY_LOCAL_MACHINE', 
    N'Software\Microsoft\MSSQLServer\MSSQLServer', 
    N'LoginMode', 
    @reg_value OUTPUT

IF @reg_value <> 2
BEGIN
    PRINT 'WARNING: Mixed mode authentication (SQL + Windows) is not enabled.'
    PRINT 'You must enable this in SQL Server Configuration Manager and restart SQL Server for SQL authentication to work.'
END
GO

-- 2. Create the database
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'password_manager')
BEGIN
    CREATE DATABASE [password_manager]
    PRINT 'Database password_manager created successfully.'
END
ELSE
BEGIN
    PRINT 'Database password_manager already exists.'
END
GO

-- 3. Create application login with proper permissions
USE [master]
GO

IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name = 'pm_server')
BEGIN
    CREATE LOGIN [pm_server] WITH PASSWORD=N'pwmanager', 
    DEFAULT_DATABASE=[password_manager], 
    CHECK_EXPIRATION=OFF, 
    CHECK_POLICY=OFF
    PRINT 'Login pm_server created successfully.'
END
ELSE
BEGIN
    PRINT 'Login pm_server already exists.'
END
GO

-- 4. Configure database user and permissions
USE [password_manager]
GO

IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'pm_server')
BEGIN
    CREATE USER [pm_server] FOR LOGIN [pm_server]
    PRINT 'Database user pm_server created successfully.'
END
ELSE
BEGIN
    PRINT 'Database user pm_server already exists.'
END
GO

-- Grant appropriate permissions (more secure than db_owner)
EXEC sp_addrolemember 'db_datareader', 'pm_server'
EXEC sp_addrolemember 'db_datawriter', 'pm_server'
EXEC sp_addrolemember 'db_ddladmin', 'pm_server'
PRINT 'Standard database permissions granted to pm_server.'
GO

-- 5. Create all tables and schema objects
PRINT 'Creating application tables and indexes...'
GO

-- User table
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'user')
BEGIN
    CREATE TABLE [user] (
        id INT IDENTITY(1,1) PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        failed_login_attempts INT NOT NULL DEFAULT 0,
        CONSTRAINT uq_username UNIQUE (username)
    )
    
    CREATE INDEX idx_username ON [user] (username)
    CREATE INDEX idx_failed_logins ON [user] (failed_login_attempts)
    PRINT 'Table [user] created successfully.'
END
ELSE
BEGIN
    PRINT 'Table [user] already exists.'
END
GO

-- Password table
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'password')
BEGIN
    CREATE TABLE password (
        id INT IDENTITY(1,1) PRIMARY KEY,
        service_name VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        notes VARCHAR(500) NULL,
        user_id INT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES [user](id) ON DELETE CASCADE
    )
    
    CREATE INDEX idx_user_id ON password (user_id)
    PRINT 'Table password created successfully.'
END
ELSE
BEGIN
    PRINT 'Table password already exists.'
END
GO

-- Audit log table
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'audit_log')
BEGIN
    CREATE TABLE audit_log (
        id INT IDENTITY(1,1) PRIMARY KEY,
        event_time DATETIME DEFAULT GETDATE(),
        event_message NVARCHAR(MAX),
        event_type VARCHAR(255),
        user_id INT NULL,
        FOREIGN KEY (user_id) REFERENCES [user](id) ON DELETE SET NULL
    )
    
    CREATE INDEX idx_event_type_user_id ON audit_log (event_type, user_id)
    CREATE INDEX idx_event_time ON audit_log (event_time)
    PRINT 'Table audit_log created successfully.'
END
ELSE
BEGIN
    PRINT 'Table audit_log already exists.'
END
GO

-- Token Blacklist table
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLE WHERE TABLE_NAME = 'token_blacklist')
BEGIN
	CREATE TABLE token_blacklist (
    id INT IDENTITY(1,1) PRIMARY KEY,
    jti NVARCHAR(36) NOT NULL UNIQUE,
    expires_at DATETIME2 NOT NULL,
    created_at DATETIME2 DEFAULT GETDATE()
	)
    
    CREATE INDEX idx_jti ON token_blacklist (jti)
    PRINT 'Table token_blacklist created successfully.'
END
ELSE
BEGIN
	PRINT('Table token_blacklist already exists.')
END
GO

-- 6. Create initial admin user if not exists
IF NOT EXISTS (SELECT 1 FROM [user] WHERE username = 'ADMIN')
BEGIN
    INSERT INTO [user] (username, password, role, failed_login_attempts)
    VALUES ('ADMIN', '$scrypt$ln=16,r=8,p=1$DaE0phQiJOTcuxeCsFaq1Q$1MZ0Uk7thd31SuJEHwZvbdMkr3pmbKmAuoyd1SQRSls', 'admin', 0)
    PRINT 'Admin user created successfully.'
END
ELSE
BEGIN
    PRINT 'Admin user already exists.'
END
GO

PRINT 'SQL Server setup completed successfully!'
GO