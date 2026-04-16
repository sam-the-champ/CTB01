import { Router } from 'express';
/*
Imports Express Router.
Router is used to create modular route handlers instead of putting everything in app.ts.
*/

import { register } from '../controllers/auth.controller';
/*
Imports the register controller function.
This is the function that handles user registration logic.
*/
import { login } from '../controllers/auth.controller';

import { refresh } from '../controllers/auth.controller';


const router = Router();
/*
Creates a new router instance.

Think of it as a mini Express app just for authentication routes.
*/


// POST /api/auth/register
router.post('/register', register);
/*
Defines a POST route:

- URL path: /register
- Method: POST
- Controller: register function

So when frontend sends:
POST /register
→ this function runs
*/
router.post('/login', login);
router.post('/refresh', refresh);


export default router;
/*
Exports the router so it can be used in the main server file (app.ts or server.ts)
*/



