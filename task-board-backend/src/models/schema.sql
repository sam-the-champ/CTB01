-- 1. Create a custom type for Roles
CREATE TYPE user_role AS ENUM ('user', 'admin');
-- Creates a custom ENUM type called "user_role"
-- This restricts role values to ONLY 'user' or 'admin'
-- Prevents invalid roles like 'manager', 'guest', etc.


-- 2. Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Unique identifier for each user
    -- UUID = universally unique ID (hard to guess)
    -- gen_random_uuid() automatically generates it

    email TEXT UNIQUE NOT NULL,
    -- User email address
    -- UNIQUE = no two users can have the same email
    -- NOT NULL = email is required

    password_hash TEXT NOT NULL,
    -- Stores hashed password (NOT plain password)
    -- bcrypt hash is stored here for security

    role user_role DEFAULT 'user',
    -- User role using the custom ENUM type
    -- Default role is 'user'
    -- Can also be 'admin'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    -- Stores when user account was created
    -- Automatically sets current time when user is inserted
);


-- 3. Refresh Tokens Table (The Session Store)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Unique ID for each refresh token record

    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    -- Links token to a specific user
    -- FOREIGN KEY relationship to users table
    -- ON DELETE CASCADE = if user is deleted, all their tokens are deleted too

    token_hash TEXT NOT NULL,
    -- Stores hashed version of refresh token (not raw token)
    -- Improves security if database is leaked

    family_id UUID NOT NULL,
    -- Groups related refresh tokens together
    -- Used for token rotation security
    -- If one token is stolen, entire "family" can be invalidated

    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Expiration date/time of the refresh token
    -- After this time, token becomes invalid

    is_revoked BOOLEAN DEFAULT FALSE,
    -- Marks whether token has been manually invalidated
    -- TRUE = token is no longer usable

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    -- When the refresh token was created
);