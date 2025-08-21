import { Router } from 'express';
import { authenticate_request } from '../services/authentication.service';
import health_check_router from './health_check.routes';
import auth_router from './auth.routes';

const router = Router();

router.use('/v1', auth_router);
router.use('/v1/health_check', health_check_router);

// Applied the authentication middleware globally
router.use(authenticate_request);

export default router;