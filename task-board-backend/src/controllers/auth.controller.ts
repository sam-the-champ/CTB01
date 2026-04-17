import { Request, Response, NextFunction } from 'express';
import { RegisterSchema } from '../utils/validator';
import * as AuthService from '../services/auth.service';


export const register = async (req: Request, res: Response) => {

  try {
    // 1. Validate data
    const validatedData = RegisterSchema.parse(req.body);
    /*
    Takes user input from req.body and validates it using Zod.

    If data is invalid:
    - Zod throws an error
    - Code jumps to catch block

    If valid:
    - returns clean data (validatedData)
    */


    // 2. Check if user already exists
    // (In a real app, you'd add a "findByEmail" service check here)
    /*
    This is a placeholder step.

    Normally you would:
    - query database
    - check if email already exists
    - prevent duplicate registration
    */


    // 3. Create user
    const newUser = await AuthService.createUser(
      validatedData.email,
      validatedData.password,
      validatedData.role
    );


    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role
      }
    });


  } catch (error: any) {
    // Zod throws errors if validation fails
    res.status(400).json({ error: error.errors || error.message });
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  

  try {
    const { email, password } = req.body;

    const result = await AuthService.loginUser(email, password);

    if (!result) {
      return res.status(401).json({ error: "Invalid credentials" });
  
    }

    // Set the Refresh Token in a cookie
    res.cookie('refreshToken', result.refreshToken, {
      // Stores the refresh token in the browser as a cookie

      httpOnly: true,
      // Prevents JavaScript from accessing the cookie (protects against XSS attacks)

      secure: true,
      // Ensures cookie is only sent over HTTPS (should be true in production)

      sameSite: 'strict',
      // Prevents CSRF by only allowing same-site requests to include this cookie

      maxAge: 7 * 24 * 60 * 60 * 1000
      
    });

    // Send the Access Token in the JSON body
    res.json({
      message: "Login successful",

      accessToken: result.accessToken,

      user: result.user
    
    });

  } catch (error) {
    next(error);

  }
};

export const refresh = async (req: Request, res: Response, next: NextFunction) => {

  try {
    const oldRefreshToken = req.cookies.refreshToken;

    if (!oldRefreshToken) {
      return res.status(401).json({ error: "No refresh token provided" });
     
    }

    const { newAccessToken, newRefreshToken } = await AuthService.refreshSession(oldRefreshToken);
    /*
    Calls the refreshSession service function.
    */


    // Replace the old cookie with the new one
    res.cookie('refreshToken', newRefreshToken, {
    

      httpOnly: true,

      secure: true,

      sameSite: 'strict',

      maxAge: 7 * 24 * 60 * 60 * 1000
     
    });

    res.json({ accessToken: newAccessToken });
 
  } catch (error: any) {
    res.status(401).json({ error: error.message });
  }
};


export const logoutAll = async (req: any, res: Response, next: NextFunction) => {

  try {
    const userId = req.user.userId;

    await AuthService.logoutAllDevices(userId);

    res.clearCookie('refreshToken');

    res.json({ message: "All sessions invalidated." });

  } catch (error) {
    next(error);
  }
};