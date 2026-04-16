import { generateAccessToken, generateRefreshToken } from '../utils/jwt.util';
import bcrypt from 'bcrypt';
/*
Imports bcrypt library.
Used to securely hash passwords so you NEVER store plain text passwords in the database.
*/

import { query } from '../config/db';
/*
Imports your database helper function.
This is what you use to run SQL queries on PostgreSQL.
*/
import { v4 as uuidv4 } from 'uuid'; 
/*
Imports UUID generator.
Used to create a unique "familyId" for refresh token rotation.
*/
import jwt from 'jsonwebtoken';

export const createUser = async (
  email: string,
  passwordRaw: string,
  role: string = 'user'
) => {
/*
Creates an async function to register a new user.

Parameters:
- email → user email
- passwordRaw → plain password from user input
- role → user role (defaults to 'user')
*/


  // Salt rounds = 12. A good balance between security and server speed.
  const salt = await bcrypt.genSalt(12);
  /*
  Generates a salt (random data added to password before hashing).
  12 rounds = strong security + acceptable performance.
  */


  const hash = await bcrypt.hash(passwordRaw, salt);
  /*
  Hashes the password using the salt.
  Result is a secure encrypted password (irreversible).
  Example output: $2b$12$WqX...
  */


  const result = await query(
    'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role',
    [email, hash, role]
  );
  /*
  Inserts new user into the database.

  SQL breakdown:
  - INSERT INTO users → add new row
  - email → user email
  - password_hash → hashed password (NOT raw password)
  - role → user role

  $1, $2, $3 = placeholders (prevents SQL injection)

  RETURNING id, email, role:
  → returns the newly created user (without password)
  */


  return result.rows[0];
  /*
  Returns the first row from the result (the created user).
  Example output:
  {
    id: "...",
    email: "user@gmail.com",
    role: "user"
  }
  */
};


export const loginUser = async (email: string, passwordRaw: string) => {

  // 1. Find user
  const userRes = await query('SELECT * FROM users WHERE email = $1', [email]);
  /*
  Queries the database to find a user with the given email.
  $1 is a placeholder to prevent SQL injection.
  */

  const user = userRes.rows[0];
  /*
  Extracts the first result (user record).
  If no user is found, this will be undefined.
  */

  if (!user) return null;
  /*
  If user does not exist → return null (invalid login).
  */


  // 2. Compare Passwords
  const isMatch = await bcrypt.compare(passwordRaw, user.password_hash);
  /*
  Compares the plain password entered by the user with the hashed password in DB.
  bcrypt.compare handles hashing internally and checks if they match.
  */

  if (!isMatch) return null;
  /*
  If password is incorrect → return null (invalid login).
  */


  // 3. Create a Session (Refresh Token Family)
  const familyId = uuidv4();
  /*
  Generates a unique ID to represent this login session.
  All refresh tokens from this session will share this familyId.
  */

  const accessToken = generateAccessToken(user.id, user.role);
  /*
  Generates a short-lived access token (e.g. 15 minutes).
  Used by frontend to access protected routes.
  */

  const refreshToken = generateRefreshToken(user.id, familyId);
  /*
  Generates a long-lived refresh token (e.g. 7 days).
  Used to request new access tokens when they expire.
  */


  // 4. Store the Hashed Refresh Token in DB
  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
  /*
  Hashes the refresh token before storing it.
  This ensures that even if DB is leaked, raw tokens are not exposed.
  */

  await query(
    'INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, $4)',
    [
      user.id,
      refreshTokenHash,
      familyId,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    ]
  );
  /*
  Stores the refresh token in the database:

  - user_id → links token to user
  - token_hash → hashed refresh token
  - family_id → tracks session group
  - expires_at → sets expiry (7 days from now)

  Date calculation:
  7 days × 24 hrs × 60 mins × 60 secs × 1000 ms
  */


  // 5. Return tokens + safe user data
  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      role: user.role
    }
  };
  /*
  Returns:
  - accessToken → for API requests
  - refreshToken → for renewing sessions
  - user info → safe data (no password)

  This is what gets sent back to frontend after login.
  */
};

export const refreshSession = async (oldRefreshToken: string) => {
  // Defines an async function that handles refreshing a user's session
  // It receives the old refresh token sent from the client

  // 1. Verify the token exists and isn't expired
  const decoded = jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET!) as any;
  /*
  Verifies and decodes the refresh token using JWT secret.

  If token is:
  - expired ❌
  - tampered ❌

  It will throw an error.

  If valid:
  - returns payload (userId, familyId, etc.)
  */

  
  // 2. Look up the token in our DB
  const tokenRes = await query(
    'SELECT * FROM refresh_tokens WHERE user_id = $1 AND family_id = $2 AND is_revoked = FALSE',
    [decoded.userId, decoded.familyId]
  );
  /*
  Queries database to find active refresh token record:

  - user_id must match decoded userId
  - family_id ensures we are in same login session group
  - is_revoked = FALSE ensures token is still valid

  This is part of token rotation security system
  */

  
  const storedToken = tokenRes.rows[0];
  /*
  Gets the first matching token record from DB
  If none found → storedToken will be undefined
  */


  // 3. SECURITY CHECK: Reuse Detection
  // If we can't find the token, or the hash doesn't match the latest one in the family,
  // someone might be trying to reuse an old token.

  const isMatch = storedToken
    ? await bcrypt.compare(oldRefreshToken, storedToken.token_hash)
    : false;
  /*
  Compares incoming refresh token with hashed version in DB.

  Why this matters:
  - Prevents token theft reuse
  - Ensures only latest token in family is valid
  */


  if (!storedToken || !isMatch) {
    // CRITICAL: Potential theft detected. Revoke the entire family!
    await query(
      'UPDATE refresh_tokens SET is_revoked = TRUE WHERE family_id = $1',
      [decoded.familyId]
    );
    /*
    If something is wrong:
    - token not found OR
    - token mismatch

    Then:
    👉 assume token theft
    👉 revoke ALL tokens in that family
    */

    throw new Error("Security breach detected. Please login again.");
    /*
    Forces user to re-login completely
    */
  }


  // 4. Everything is fine. Generate NEW pair
  const newAccessToken = generateAccessToken(decoded.userId, storedToken.role);
  /*
  Creates a new short-lived access token (e.g. 15 mins)
  Used for API authentication
  */


  const newRefreshToken = generateRefreshToken(decoded.userId, decoded.familyId);
  /*
  Creates a new refresh token but keeps same familyId
  This is called "token rotation"
  */


  const newHash = await bcrypt.hash(newRefreshToken, 10);
  /*
  Hashes the new refresh token before storing it in DB
  */


  // 5. Update the DB with the new token hash
  await query(
    'UPDATE refresh_tokens SET token_hash = $1 WHERE id = $2',
    [newHash, storedToken.id]
  );
  /*
  Updates database with new refresh token hash
  Old refresh token is now invalid
  */


  return { newAccessToken, newRefreshToken };
  
};
