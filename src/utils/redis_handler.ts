import { redis_cli } from '../db/connect_db';


/**
 * 
 * @name : set_access_token_redis
 * @Desc : For setting access_token in redis db
 * 
 */


async function set_access_token_redis(user_id: number, access_token: string): Promise<void> {
    await redis_cli.set(`${user_id}:access_tokens:${access_token}`, 'true', 'EX', Number(process.env.ACCESS_REDIS_EXPIRY) * 60);
}


/**
 * 
 * @name : get_access_token_redis
 * @Desc : For getting access_token from redis db
 * 
 */


async function get_access_token_redis(user_id: number, access_token: string): Promise<string | null> {
    return await redis_cli.get(`${user_id}:access_tokens:${access_token}`);
}


/**
 * 
 * @name : set_forgot_pass_otp_redis
 * @Desc : For setting forgot password otp in redis db
 * 
 */


async function set_forgot_pass_otp_redis(user_id: string, otp: string): Promise<void> {
    await redis_cli.set(`${user_id}:forgot_password_otp`, otp, `EX`, Number(process.env.FORGOT_PASSWORD_OTP_EXPIRE) * 60);
}


/**
 * 
 * @name : get_forgot_pass_otp_redis
 * @Desc : For getting forgot password otp from redis db
 * 
 */


async function get_forgot_pass_otp_redis(user_id: string): Promise<string | null> {
    return await redis_cli.get((`${user_id}:forgot_password_otp`));
}


/**
 * 
 * @name : set_forgot_pass_secret_redis
 * @Desc : For setting forgot password secret in redis db
 * 
 */


async function set_forgot_pass_secret_redis(user_id: string, forgot_pass_secret: string): Promise<void> {
    await redis_cli.set(`${user_id}:forgot_password_secret`, forgot_pass_secret, `EX`, Number(process.env.FORGOT_PASSWORD_SECRET_EXPIRE) * 60);
}


/**
 * 
 * @name : get_forgot_pass_secret_redis
 * @Desc : For getting forgot password secret from redis db
 * 
 */


async function get_forgot_pass_secret_redis(user_id: string): Promise<string | null> {
    return await redis_cli.get(`${user_id}:forgot_password_secret`);
}


/**
 * 
 * @name : delete_from_redis
 * @Desc : For deleting single key data from redis db
 * 
 */


async function delete_from_redis(key: string): Promise<void> {
    await redis_cli.del(`${key}`);  // Deleting key from redis
}


/**
 * 
 * @name : delete_multiple_from_redis
 * @Desc : For deleting multiple data from redis db
 * - EX ${user_id}/${access_token}/*
 * 
 */


async function delete_multiple_from_redis(path: string): Promise<void> {
    let cursor = '0', pattern = path;

    do {
        const result = await redis_cli.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
        cursor = result[0];
        const keys = result[1];

        if (keys.length > 0) {
            await redis_cli.del(keys);
        }
    } while (cursor !== '0');
}


/**
 * 
 * @name : get_count_of_all_permissions
 * @Desc : For getting all permissions on the basis of method type from redis db
 * 
 */


async function get_count_of_all_permissions(user_type: string, method_type: string): Promise<number | null> {
    return await redis_cli.scard(`permissions:${user_type}:${method_type}`);
}


/**
 * 
 * @name : get_user_permissions_redis
 * @Desc : For getting user permissions from redis db
 * 
 */


async function get_user_permissions_redis(user_type: string, api_route: string, method_type: string): Promise<number | null> {
    return await redis_cli.sismember(`permissions:${user_type}:${method_type}`, api_route);
}


/**
 * 
 * @name : set_user_permissions_redis
 * @Desc : For setting user permissions in redis db
 * 
 */

async function set_user_permissions_redis(permissions: any[]) {
    // Create an object to hold categorized permissions
    const categorizedPermissions: any = {
        'admin': { 'get': [], 'post': [], 'put': [], 'patch': [], 'delete': [] },
        'user': { 'get': [], 'post': [], 'put': [], 'patch': [], 'delete': [] }
    };

    // Categorize permissions
    for (const perm of permissions) {
        const { user_type, method_type, route } = perm;
        const method = method_type.toLowerCase();

        if (categorizedPermissions[user_type] && categorizedPermissions[user_type][method]) {
            categorizedPermissions[user_type][method].push(route);
        }
    }

    // Add permissions to Redis
    for (const userType in categorizedPermissions) {
        for (const method in categorizedPermissions[userType]) {
            const key = `permissions:${userType}:${method}`;
            const routes = categorizedPermissions[userType][method];

            // Remove old permissions
            await redis_cli.del(key);

            if (routes.length > 0) {
                await redis_cli.sadd(key, ...routes, );
            }
        }
    }
}


export {
    set_access_token_redis,
    get_access_token_redis,
    delete_from_redis,
    set_forgot_pass_otp_redis,
    get_forgot_pass_otp_redis,
    set_forgot_pass_secret_redis,
    get_forgot_pass_secret_redis,
    delete_multiple_from_redis,
    get_user_permissions_redis,
    set_user_permissions_redis,
    get_count_of_all_permissions
};