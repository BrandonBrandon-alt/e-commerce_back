-- Migration: Remove deprecated account_locked_until column
-- Date: 2025-10-07
-- Description: Removes the account_locked_until column from users table
--              Account lockout is now managed in Redis via AccountLockoutRedisService

-- Drop the column if it exists
ALTER TABLE users DROP COLUMN IF EXISTS account_locked_until;

-- Optional: Add a comment to document the change
COMMENT ON TABLE users IS 'Account lockout is managed in Redis, not in database';
