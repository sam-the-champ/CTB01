import { Router } from 'express';
// Imports Express Router to create modular routes

import { authenticateJWT } from '../middleware/auth.middleware';
// Imports your authentication middleware
// This middleware verifies JWT and attaches user data to req.user


const router = Router();
// Creates a new router instance (a mini app for grouping routes)


// This route is PROTECTED. 
// If there is no valid token, 'authenticateJWT' will stop the request.
router.get('/me', authenticateJWT, (req: any, res) => {
  /*
  Defines a GET route at /me

  Flow:
  - Request hits this route
  - authenticateJWT runs FIRST
  - If token is valid → continue
  - If not → request is blocked
  */

  res.json({
    message: "Welcome to your private profile",
    // Sends a success message back to the client

    user: req.user
    // Returns user data that was attached by authenticateJWT middleware
    // Contains: userId and role
  });
});

export default router;
// Exports the router so it can be used in your main app (app.ts)