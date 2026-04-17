import { Router } from 'express';

import { authenticateJWT } from '../middleware/auth.middleware';

const router = Router();

router.get('/me', authenticateJWT, (req: any, res) => {

  res.json({
    message: "Welcome to your private profile",

    user: req.user
    
  });
});

export default router;
