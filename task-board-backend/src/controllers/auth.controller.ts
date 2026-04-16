import { Request, Response, NextFunction } from 'express';
/*
Imports Express types:
- Request → represents incoming HTTP request
- Response → used to send response back to client
*/

import { RegisterSchema } from '../utils/validator';
/*
Imports Zod schema used to validate registration data
Ensures email/password are correct before processing
*/

import * as AuthService from '../services/auth.service';
/*
Imports all functions from auth.service file
This is where database logic lives (createUser, login, etc.)
*/


export const register = async (req: Request, res: Response) => {
/*
Defines the REGISTER controller function.

It handles:
- incoming request (req)
- outgoing response (res)
*/

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
    /*
    Calls service layer function to:
    - hash password (bcrypt)
    - insert user into database
    - return created user
    */


    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role
      }
    });
    /*
    Sends success response to client:

    Status 201 = "Created"

    Returns:
    - success message
    - user data (WITHOUT password for security)
    */


  } catch (error: any) {
    // Zod throws errors if validation fails
    res.status(400).json({ error: error.errors || error.message });
    /*
    If anything fails:
    - validation error (Zod)
    - database error
    - server error

    Returns:
    - 400 Bad Request
    - error details
    */
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  // Defines an async login controller function with request, response, and next (error handler)

  try {
    const { email, password } = req.body;
    // Extracts email and password sent from the frontend (login form)

    const result = await AuthService.loginUser(email, password);
    // Calls the login service:
    // - checks if user exists
    // - verifies password
    // - generates access + refresh tokens
    // - stores refresh token in DB

    if (!result) {
      return res.status(401).json({ error: "Invalid credentials" });
      // If login fails (wrong email or password):
      // send 401 Unauthorized response with error message
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
      // Sets cookie expiration to 7 days (in milliseconds)
    });

    // Send the Access Token in the JSON body
    res.json({
      message: "Login successful",
      // Success message sent back to client

      accessToken: result.accessToken,
      // Access token sent in response body (used for authenticated API calls)

      user: result.user
      // Safe user data (id, email, role — no password)
    });

  } catch (error) {
    next(error);
    // If any error occurs:
    // pass it to Express error-handling middleware
  }
};

export const refresh = async (req: Request, res: Response, next: NextFunction) => {
  // Defines the refresh controller function
  // Handles requests to generate a new access token using a refresh token

  try {
    const oldRefreshToken = req.cookies.refreshToken;
    /*
    Retrieves the refresh token from cookies.

    req.cookies comes from cookie-parser middleware.
    The cookie name is 'refreshToken'.
    */

    if (!oldRefreshToken) {
      return res.status(401).json({ error: "No refresh token provided" });
      /*
      If no refresh token is found:
      - return 401 Unauthorized
      - user is not logged in or session expired
      */
    }

    const { newAccessToken, newRefreshToken } = await AuthService.refreshSession(oldRefreshToken);
    /*
    Calls the refreshSession service function.

    This will:
    - verify the refresh token
    - check DB for validity
    - detect token reuse (security)
    - generate new access + refresh tokens
    - rotate (replace) the refresh token in DB
    */


    // Replace the old cookie with the new one
    res.cookie('refreshToken', newRefreshToken, {
      /*
      Stores the new refresh token in the cookie,
      replacing the old one (token rotation)
      */

      httpOnly: true,
      /*
      Prevents JavaScript from accessing the cookie
      Protects against XSS attacks
      */

      secure: true,
      /*
      Cookie only sent over HTTPS
      Should be true in production
      */

      sameSite: 'strict',
      /*
      Prevents CSRF attacks
      Only same-site requests can include this cookie
      */

      maxAge: 7 * 24 * 60 * 60 * 1000
      /*
      Sets cookie expiry to 7 days
      Matches refresh token expiration
      */
    });

    res.json({ accessToken: newAccessToken });
    /*
    Sends the new access token back to the client

    Frontend will use this token for authenticated API requests
    */

  } catch (error: any) {
    res.status(401).json({ error: error.message });
    /*
    If anything fails:
    - invalid token
    - expired token
    - security breach

    Return 401 Unauthorized with error message
    */
  }
};