USE password_manager;
GO

-- Delete existing logs (optional, use with caution)
-- DELETE FROM audit_log where user_id >= 1;

-- Declare variables for date range
DECLARE @start_date DATETIME = DATEADD(DAY, -30, CAST(GETDATE() AS DATE)); -- Start date: 30 days ago
DECLARE @end_date DATETIME = GETDATE(); -- End date: today

-- Create a temporary numbers table to generate rows
CREATE TABLE #temp_numbers (
    num INT
);

-- Insert numbers from 0 to 29 (for 30 days)
INSERT INTO #temp_numbers (num)
SELECT number
FROM (
    SELECT 0 AS number UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION
    SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION
    SELECT 10 UNION SELECT 11 UNION SELECT 12 UNION SELECT 13 UNION SELECT 14 UNION
    SELECT 15 UNION SELECT 16 UNION SELECT 17 UNION SELECT 18 UNION SELECT 19 UNION
    SELECT 20 UNION SELECT 21 UNION SELECT 22 UNION SELECT 23 UNION SELECT 24 UNION
    SELECT 25 UNION SELECT 26 UNION SELECT 27 UNION SELECT 28 UNION SELECT 29
) AS numbers;

-- Insert logs for each day
INSERT INTO audit_log (event_time, event_message, event_type, user_id)
SELECT
    DATEADD(SECOND, CAST(RAND() * 86400 AS INT), DATEADD(DAY, num, CAST(@start_date AS DATETIME))) AS event_time,
    'Sample event on ' + CONVERT(VARCHAR, DATEADD(DAY, num, @start_date), 23) AS event_message,
    CASE FLOOR(RAND() * 4)
        WHEN 0 THEN 'LOGIN'
        WHEN 1 THEN 'LOGOUT'
        WHEN 2 THEN 'PASSWORD_CHANGE'
        WHEN 3 THEN 'AUDIT_LOG_VIEW'
    END AS event_type,
    1 AS user_id
FROM
    #temp_numbers;

-- Drop the temporary numbers table
DROP TABLE #temp_numbers;
GO