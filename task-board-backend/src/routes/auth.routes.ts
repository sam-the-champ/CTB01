import { Router } from 'express';

import { register } from '../controllers/auth.controller';

import { login } from '../controllers/auth.controller';

import { refresh } from '../controllers/auth.controller';


const router = Router();



// POST /api/auth/register
router.post('/register', register);

router.post('/login', login);
router.post('/refresh', refresh);


export default router;




