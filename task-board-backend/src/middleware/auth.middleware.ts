import { Request, Response, NextFunction } from 'express';

import jwt from 'jsonwebtoken';

interface AuthRequest extends Request {

  user?: {
    userId: string;

    role: string;
  };
}


export const authenticateJWT = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  // Reads the Authorization header from the request


  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: "Access denied. No token provided." });
   
  }


  const token = authHeader.split(' ')[1];


  try {
    // 2. Verify the token
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as any;


    // 3. Attach the user data to the request object
    req.user = {
      userId: decoded.userId,
      role: decoded.role
    };
    next();

  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired token." });
  }
};

export const authorizeRole = (role: 'user' | 'admin') => {

  return (req: AuthRequest, res: Response, next: NextFunction) => {
    // Returns middleware function that will run during a request

    if (!req.user || (req.user.role !== role && req.user.role !== 'admin')) {

      return res.status(403).json({
        error: "Forbidden: You do not have the required permissions."
      });
     
    }

    next();
   
  };
};