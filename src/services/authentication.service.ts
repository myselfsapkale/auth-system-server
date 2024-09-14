import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/api_response';
import { async_handler } from '../utils/async_handler';
import { get_user_from_token } from './common_helper.service';
import { get_access_token_redis, get_user_permissions_redis, set_user_permissions_redis } from '../utils/redis_handler';
import { get_user_permission } from '../model/auth.model';
import { checkPermissionsExists } from './common_helper.service';


/**
 * 
 * @name : authenticate_request
 * @Desc : For authenticate user with access token
 * 
 */


const authenticate_request = async_handler(async (req: Request, res: Response, next: NextFunction) => {
    try {
        const auth_header = req.headers['authorization'],
            corelation_id = req.headers['nonce'],
            token = auth_header && auth_header.split(' ')[1];

        if (!token) return res.status(401).json(new ApiError(401, 'Please send a token'));   // If user does not send token in the request then rejecting it

        if (!corelation_id) return res.status(401).json(new ApiError(401, 'Please send corelation / Nonce'));   // If user does not send corelation / Nonce in the request then rejecting it

        let { user_id, user_type } = get_user_from_token(token, "access_token");    // Reading user details from given refresh token

        let is_token_exists = await get_access_token_redis(user_id, token); // Checking access token exists or not in db
        if (!is_token_exists) return res.status(401).json(new ApiError(401, 'Token is blocked'));   // If we want to block the access token we will delete it from redis

        // Extract the URL path without query parameters
        const url_path = req.path; // This automatically excludes query parameters

        // Split the path into segments
        const segments = url_path.split('/').filter(segment => segment.length > 0);

        // Get the last segment
        const last_segment = segments.length > 0 ? segments[segments.length - 1] : '';
        const methodType = req.method;

        // Check permissions exists or not in redis
        if (!await checkPermissionsExists()) {
            let user_permissions = await get_user_permission();  // Getting all the permissions from DB
            await set_user_permissions_redis(user_permissions); // Setting permissions in Redis
        }

        // Authorization
        let permissions = await get_user_permissions_redis(user_type.toLowerCase(), `/${last_segment}`, methodType.toLowerCase());   //  Getting users permissions from redis
        if (!permissions) return res.status(401).json(new ApiError(401, `You don't have permission for the feature !!`));

        next();
    }
    catch (err) {
        if (err instanceof Error) {
            if (err.message === 'jwt expired') return res.status(401).json(new ApiError(401, 'Access token expired'));
            else return res.status(401).json(new ApiError(401, err.message));
        }
        else {
            return res.status(401).json(new ApiError(401, 'Error in authenticate token'));
        }
    }
});


export { authenticate_request };