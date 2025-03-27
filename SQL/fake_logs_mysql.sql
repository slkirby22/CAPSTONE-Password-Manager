USE password_manager;

-- Delete existing logs (optional, use with caution)
-- DELETE FROM audit_log where user_id >= 1;

-- Insert fake logs for the past 30 days
SET @start_date = DATE_SUB(CURRENT_DATE, INTERVAL 30 DAY); -- Start date: 30 days ago
SET @end_date = CURRENT_DATE; -- End date: today

-- Create a temporary numbers table to generate rows
CREATE TEMPORARY TABLE temp_numbers (
    num INT
);

-- Insert numbers from 0 to 29 (for 30 days)
INSERT INTO temp_numbers (num)
VALUES (0), (1), (2), (3), (4), (5), (6), (7), (8), (9),
       (10), (11), (12), (13), (14), (15), (16), (17), (18), (19),
       (20), (21), (22), (23), (24), (25), (26), (27), (28), (29);

-- Insert logs for each day
INSERT INTO audit_log (event_time, event_message, event_type, user_id)
SELECT
    DATE_ADD(@start_date, INTERVAL num DAY) + INTERVAL FLOOR(RAND() * 86400) SECOND AS event_time, -- Random time within the day
    CONCAT('Sample event on ', DATE(DATE_ADD(@start_date, INTERVAL num DAY))) AS event_message, -- Event message
    CASE FLOOR(RAND() * 4) -- Random event type
        WHEN 0 THEN 'LOGIN'
        WHEN 1 THEN 'LOGOUT'
        WHEN 2 THEN 'PASSWORD_CHANGE'
        WHEN 3 THEN 'AUDIT_LOG_VIEW'
    END AS event_type,
    1 AS user_id -- Assuming user_id = 1 exists in the user table
FROM
    temp_numbers;

-- Drop the temporary numbers table
DROP TEMPORARY TABLE temp_numbers;