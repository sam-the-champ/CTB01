import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.middleware';
import * as TaskController from '../controllers/task.controllers';

const router = Router();

// All tasks routes require a login
router.use(authenticateJWT); 

router.post('/', TaskController.create);
router.get('/', TaskController.list);
// For the update, i will use the ID in the URL
router.patch('/:id/status', TaskController.updateStatus);

export default router;