import { redis_cli } from '../db/connect_db';


/**
 * 
 * @name : set_access_token_redis
 * @Desc : For setting access_token in redis db
 * 
 */


async function set_access_token_redis(user_id: number, access_token: string): Promise<void> {
    await redis_cli.set(`${user_id}:access_tokens:${access_token}`, 'true', 'EX', process.env.ACCESS_REDIS_EXPIRY ? Number(process.env.ACCESS_REDIS_EXPIRY) * 3600 : 5 * 3600);
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
    await redis_cli.set(`${user_id}:forgot_password_otp`, otp, `EX`, process.env.FORGOT_PASSWORD_OTP_EXPIRE ? Number(process.env.FORGOT_PASSWORD_OTP_EXPIRE) : 120)
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
    await redis_cli.set(`${user_id}:forgot_password_secret`, forgot_pass_secret, `EX`, process.env.FORGOT_PASSWORD_OTP_EXPIRE ? Number(process.env.FORGOT_PASSWORD_SECRET_EXPIRE) : 120);
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
 * @name : get_user_permissions_redis
 * @Desc : For getting user permissions from redis db
 * 
 */


async function get_user_permissions_redis(user_type: string): Promise<string | null> {
    return await redis_cli.get(`permissions:${user_type}`);
}

export {set_access_token_redis, get_access_token_redis, delete_from_redis, set_forgot_pass_otp_redis, get_forgot_pass_otp_redis, set_forgot_pass_secret_redis, get_forgot_pass_secret_redis, get_user_permissions_redis, delete_multiple_from_redis  };