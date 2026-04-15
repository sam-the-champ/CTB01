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

