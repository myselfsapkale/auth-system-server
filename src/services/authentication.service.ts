import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/api_response';
import { async_handler } from '../utils/async_handler';
import { get_user_from_token } from './common_helper.service';
import { get_access_token_redis, get_user_permissions_redis, set_user_permissions_redis } from '../utils/redis_handler';
import { get_user_permission } from '../model/auth.model';
import { checkPermissionsExists } from './common_helper.service';
import logger from '../utils/elk_logger';


/**
 *
 * @name : authenticate_request
 * @Desc : For authenticate user with access token
 *
 */


const authenticate_request = async_handler(async (req: Request, res: Response, next: NextFunction) => {
    try {
        logger.info(req, 'Authentication started');
        const auth_header = req.headers['authorization'],
            correlation_id = req.headers['nonce'],
            token = auth_header && auth_header.split(' ')[1];

        if (!token) {
            logger.warn(req, `Authentication failed - missing authorization token (has_auth_header: ${!!auth_header})`);
            return res.status(401).json(new ApiError(401, 'Please send a token'));
        }

        if (!correlation_id) {
            logger.warn(req, 'Authentication failed - missing correlation ID');
            return res.status(401).json(new ApiError(401, 'Please send correlation / Nonce'));
        }

        let { user_id, user_type } = get_user_from_token(token, "access_token");    // Reading user details from given refresh token

        let is_token_exists = await get_access_token_redis(user_id, token); // Checking access token exists or not in db
        if (!is_token_exists) {
            logger.warn(req, `Authentication failed - token is blocked or expired for user_id: ${user_id}, type: ${user_type}`);
            return res.status(401).json(new ApiError(401, 'Token is blocked'));
        }

        // Extract the URL path without query parameters
        const url_path = req.path; // This automatically excludes query parameters

        // Split the path into segments
        const segments = url_path.split('/').filter(segment => segment.length > 0);

        // Get the last segment
        const last_segment = segments.length > 0 ? segments[segments.length - 1] : '';
        const methodType = req.method;

        // Check permissions exists or not in redis
        if (!await checkPermissionsExists()) {
            logger.info(req, `Loading permissions from database to Redis cache for user_id: ${user_id}, type: ${user_type}`);
            let user_permissions = await get_user_permission();  // Getting all the permissions from DB
            await set_user_permissions_redis(user_permissions); // Setting permissions in Redis
        }

        // Authorization
        let permissions = await get_user_permissions_redis(user_type.toLowerCase(), `/${last_segment}`, methodType.toLowerCase());   //  Getting users permissions from redis
        if (!permissions) {
            logger.warn(req, `Authentication failed - insufficient permissions for user_id: ${user_id}, type: ${user_type}, endpoint: /${last_segment}, method: ${methodType}`);
            return res.status(401).json(new ApiError(401, `You don't have permission for the feature !!`));
        }

        logger.info(req, `Authentication successful for user_id: ${user_id}, type: ${user_type}, endpoint: /${last_segment}, method: ${methodType}`);

        // Adding user_id and user_type in request object for further use
        req.body.token_user_id = user_id;
        req.body.token_user_type = user_type;

        next();
    }
    catch (err) {
        if (err instanceof Error) {
            if (err.message === 'jwt expired') {
                logger.warn(req, `Authentication failed - JWT token expired: ${err.message}`);
                return res.status(401).json(new ApiError(401, 'Access token expired'));
            } else {
                logger.error(req, err, 'Authentication failed - JWT error');
                return res.status(401).json(new ApiError(401, err.message));
            }
        }
        else {
            logger.error(req, `Authentication failed - unknown error: ${String(err)} (${typeof err})`);
            return res.status(401).json(new ApiError(401, 'Error in authenticate token'));
        }
    }
});


export { authenticate_request };
