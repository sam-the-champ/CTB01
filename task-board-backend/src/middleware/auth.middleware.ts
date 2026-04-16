import { Request, Response, NextFunction } from 'express';
// Imports Express types:
// - Request → incoming request
// - Response → outgoing response
// - NextFunction → used to pass control to next middleware

import jwt from 'jsonwebtoken';
// Imports JWT library used to verify access tokens


// We extend the Express Request type to include 'user'
interface AuthRequest extends Request {
  // Creates a custom request type (AuthRequest)
  // so we can safely attach user data to req.user

  user?: {
    // Optional user object (may or may not exist)
    userId: string;
    // Stores the user ID extracted from the token

    role: string;
    // Stores the user's role (e.g. 'user' or 'admin')
  };
}


export const authenticateJWT = (req: AuthRequest, res: Response, next: NextFunction) => {
  // Defines middleware function to protect routes
  // It checks if a valid JWT access token is provided

  // 1. Get the token from the 'Authorization' header
  // Standard format is: "Bearer <token>"
  const authHeader = req.headers.authorization;
  // Reads the Authorization header from the request


  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: "Access denied. No token provided." });
    /*
    If:
    - no Authorization header OR
    - it doesn't start with "Bearer "

    Then:
    → deny access (401 Unauthorized)
    */
  }


  const token = authHeader.split(' ')[1];
  /*
  Extracts the actual token from the header.

  Example:
  "Bearer abc123.xyz"
  → split → ["Bearer", "abc123.xyz"]
  → token = "abc123.xyz"
  */


  try {
    // 2. Verify the token
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as any;
    /*
    Verifies the token using your secret key.

    If token is:
    - valid → returns decoded payload
    - expired/tampered → throws error

    decoded contains:
    - userId
    - role
    */


    // 3. Attach the user data to the request object
    req.user = {
      userId: decoded.userId,
      role: decoded.role
    };
    /*
    Adds user info to the request object.

    This allows next functions (controllers) to access:
    req.user.userId
    req.user.role
    */


    // 4. Move to the next function (the Controller)
    next();
    /*
    Passes control to the next middleware or route handler.

    If token is valid → request continues
    */

  } catch (error) {
    // If token is expired or tampered with, jwt.verify throws an error
    return res.status(403).json({ error: "Invalid or expired token." });
    /*
    If verification fails:
    → return 403 Forbidden
    → token is invalid or expired
    */
  }
};

export const authorizeRole = (role: 'user' | 'admin') => {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        if(!req.user || (req.user.role !== role && req.user.role !== 'admin')) {
            return res.status(403).json({ error: "Forbidden: you do not have the required permissions."});
        }
        next();
    };
};