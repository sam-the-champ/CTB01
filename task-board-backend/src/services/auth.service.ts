import { generateAccessToken, generateRefreshToken } from '../utils/jwt.util';
import bcrypt from 'bcrypt';
import * as AuditService from './audit.service';

import { query } from '../config/db';

import { v4 as uuidv4 } from 'uuid'; 

import jwt from 'jsonwebtoken';

export const createUser = async (
  email: string,
  passwordRaw: string,
  role: string = 'user'
) => {

  const salt = await bcrypt.genSalt(12);



  const hash = await bcrypt.hash(passwordRaw, salt);
 


  const result = await query(
    'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role',
    [email, hash, role]
  );
 


  return result.rows[0];
 
};


export const loginUser = async (email: string, passwordRaw: string) => {

  // 1. Find user
  const userRes = await query('SELECT * FROM users WHERE email = $1', [email]);


  const user = userRes.rows[0];
  if (!user) return null;
 


  // 2. Compare Passwords
  const isMatch = await bcrypt.compare(passwordRaw, user.password_hash);
  

  if (!isMatch) return null;
 
  const familyId = uuidv4();
 

  const accessToken = generateAccessToken(user.id, user.role);
 
  const refreshToken = generateRefreshToken(user.id, familyId);
 


  // 4. Store the Hashed Refresh Token in DB
  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

  await query(
    'INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, $4)',
    [
      user.id,
      refreshTokenHash,
      familyId,
      new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    ]
  );
 
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
 
};

export const refreshSession = async (oldRefreshToken: string) => {
 
  const decoded = jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET!) as any;
 
  const tokenRes = await query(
    'SELECT * FROM refresh_tokens WHERE user_id = $1 AND family_id = $2 AND is_revoked = FALSE',
    [decoded.userId, decoded.familyId]
  );

  
  const storedToken = tokenRes.rows[0];
 

  const isMatch = storedToken
    ? await bcrypt.compare(oldRefreshToken, storedToken.token_hash)
    : false;



  if (!storedToken || !isMatch) {
    // CRITICAL: Potential theft detected. Revoke the entire family!
    await query(
      'UPDATE refresh_tokens SET is_revoked = TRUE WHERE family_id = $1',
      [decoded.familyId]
    );
  

    throw new Error("Security breach detected. Please login again.");
   
  }


  
  const newAccessToken = generateAccessToken(decoded.userId, storedToken.role);

  const newRefreshToken = generateRefreshToken(decoded.userId, decoded.familyId);


  const newHash = await bcrypt.hash(newRefreshToken, 10);
 
  await query(
    'UPDATE refresh_tokens SET token_hash = $1 WHERE id = $2',
    [newHash, storedToken.id]
  );


  return { newAccessToken, newRefreshToken };
  
};

export const logoutAllDevices = async (userId: string) => {
  
  await query(
    'UPDATE refresh_tokens SET is_revoked = TRUE WHERE user_id = $1',
    [userId]
    // Parameter passed to safely inject userId into SQL query
  );


  // 2. Audit the action
  await AuditService.logAction(
    userId,
    

    'GLOBAL_LOGOUT',

    'SESSION',

    userId,

    { reason: "User requested global logout" }
  
  );


  return { message: "Logged out from all devices successfully." };
};
