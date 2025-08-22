import { Request, Response } from 'express';
import { pool } from '../db/connect_db';
import { PoolConnection } from 'mysql2/promise';
import { ApiResponse, ApiError } from '../utils/api_response';
import { async_handler } from '../utils/async_handler';
import { get_user_from_email, get_user_from_id, check_phone_exists, insert_new_user, insert_refresh_token, insert_access_token, update_access_token, get_refresh_token_id_from_refresh_token, delete_refresh_token_from_refresh_token_id, delete_all_refresh_token_of_user, update_user, insert_user_permission, get_user_permission } from '../model/auth.model';
import { get_user_details, get_bcrypt_password, generate_token, validate_password, generate_otp, generate_secret, set_auth_cookie } from '../services/auth.service';
import { get_current_UTC_time, check_all_required_keys_data, get_user_from_token } from '../services/common_helper.service';
import { send_email_otp } from '../services/nodemailer_helper.service';
import { set_access_token_redis, set_forgot_pass_otp_redis, delete_from_redis, delete_multiple_from_redis, get_forgot_pass_otp_redis, set_forgot_pass_secret_redis, get_forgot_pass_secret_redis, set_user_permissions_redis } from '../utils/redis_handler';
import { passport } from '../services/sso_login_helper.service';
import { GoogleAuthUser } from '../interfaces/auth.interface';
import logger from '../utils/elk_logger';


/**
 *
 * @name : register
 * @route : /auth/v1/register
 * @method type : post
 * @Desc :
 * - For inserting new user into DB
 * - Added transitions here
 *
 */


const register = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Registration attempt started');

  let body = req.body;
  let required_keys = ["user_first_name", "user_type", "user_last_name", "user_email", "user_phone", "password"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));

  let new_user = get_user_details(body);   // Creating new user object adding user information here

  logger.info(req, `Checking email uniqueness for registration - email: ${new_user.user_email}, type: ${new_user.user_type}`);

  let user_details = await get_user_from_email(new_user.user_email);   // Checking whether email already exists or not
  if (user_details.length > 0) {
    logger.warn(req, `Registration failed - email already exists: ${new_user.user_email} (${user_details.length} existing records)`);
    return res.status(400).json(new ApiError(400, "Email is already exists !!"));
  }

  logger.info(req, `Checking phone number uniqueness for registration - phone: ${new_user.user_phone}`);

  const is_phone_exists = await check_phone_exists(new_user.user_phone);   // Checking whether phone already exists or not
  if (is_phone_exists) {
    logger.warn(req, `Registration failed - phone number already exists: ${new_user.user_phone}`);
    return res.status(400).json(new ApiError(400, "Phone number is already exists !!"));
  }

  logger.info(req, `Starting password hashing for registration - email: ${new_user.user_email}`);

  new_user.password = await get_bcrypt_password(new_user.password, process.env.PASSWORD_TOKEN_KEY as string)  // Here we are hashing the {user_password}

  logger.info(req, `Password hashing completed for registration - email: ${new_user.user_email}`);

  logger.info(req, `Starting database transaction for user registration - email: ${new_user.user_email}`);

  let connection: PoolConnection | null = null;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction(); // Start transaction

    logger.info(req, `Inserting new user into database - email: ${new_user.user_email}`);

    let new_user_id = await insert_new_user(new_user, connection);   // Here we are inserting new user in DB

    logger.info(req, `User created successfully, generating authentication tokens - user_id: ${new_user_id}, email: ${new_user.user_email}`);

    let new_refresh_token = generate_token(new_user_id, new_user.user_type, process.env.REFRESH_TOKEN_KEY as string, Number(process.env.REFRESH_EXPIRY));   // Here generating json web token
    let new_access_token = generate_token(new_user_id, new_user.user_type, process.env.ACCESS_TOKEN_KEY as string, Number(process.env.ACCESS_EXPIRY));    // Here generating json web token

    let current_date_time = get_current_UTC_time();   // Getting UTC current time

    logger.info(req, `Storing authentication tokens in database - user_id: ${new_user_id}`);

    let new_refresh_token_id = await insert_refresh_token({ refresh_token: new_refresh_token, user_id: new_user_id, created_on: current_date_time, updated_on: current_date_time }, connection);   // Here we are setting refresh token in DB
    await insert_access_token({ access_token: new_access_token, refresh_token_id: new_refresh_token_id, user_id: new_user_id, created_on: current_date_time, updated_on: current_date_time }, connection);    // Here we are setting access token in DB

    await connection.commit();    // Commit transaction

    logger.info(req, `Database transaction committed successfully - user_id: ${new_user_id}`);

    logger.info(req, `Caching access token in Redis - user_id: ${new_user_id}`);

    await set_access_token_redis(new_user_id, new_access_token);  // Storing access_token in redis for user sessions

    logger.info(req, `User registration completed successfully - user_id: ${new_user_id}, email: ${new_user.user_email}, type: ${new_user.user_type}`);

    return res.status(201).json(new ApiResponse(201, { user_id: new_user_id, user_type: new_user.user_type, refresh_token: new_refresh_token, access_token: new_access_token }, "User created successfully !!"));
  }
  catch (err: unknown) {
    if (err instanceof Error) {
      logger.error(req, err, `Registration failed during database transaction - email: ${new_user.user_email}`);
    } else {
      logger.error(req, `Registration failed during database transaction - email: ${new_user.user_email}, unknown error: ${String(err)}`);
    }

    if (connection) {
      logger.info(req, `Rolling back database transaction due to registration error - email: ${new_user.user_email}`);
      await connection.rollback();    // Rollback transaction on error
    }

    if (err instanceof Error) {
      return res.status(400).json(new ApiError(400, err.message));
    } else {
      return res.status(400).json(new ApiError(400, 'Error in registrations !!'));
    }
  }
  finally {
    if (connection) {
      connection.release();   // Released the connection finally
    }
  }
});


/**
 *
 * @name : sign_in
 * @route : /auth/v1/sign_in
 * @method_type : post
 * @Desc :
 * - For sign_in
 * - Added transitions here
 *
 */


const sign_in = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Sign in attempt started');

  let body = req.body;
  let required_keys = ["user_email", "password"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { user_email, password } = req.body;

  logger.info(req, `Checking user existence for sign in - email: ${user_email}`);

  let user_details = await get_user_from_email(user_email);   // Checking whether email already exists or not
  if (user_details.length == 0) {
    logger.warn(req, `Sign in failed - email does not exist: ${user_email}`);
    return res.status(400).json(new ApiError(400, "Email does not exists !!"));
  }

  logger.info(req, `User found, validating account status - email: ${user_email}, user_id: ${user_details[0].id}, type: ${user_details[0].user_type}`);

  if (user_details[0]['is_active'] == 0) {
    logger.warn(req, `Sign in failed - user account is inactive: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "User is not active !!"));
  }
  if (user_details[0]['is_sso'] == 1) {
    logger.warn(req, `Sign in failed - SSO user attempting regular login: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "We already have your email registered with us from SSO !!"));
  }

  logger.info(req, `Account status validated, checking password - email: ${user_email}, user_id: ${user_details[0].id}`);

  let pass_check = await validate_password(user_details[0].password, password, process.env.PASSWORD_TOKEN_KEY as string);   // Validating password
  if (!pass_check) {
    logger.warn(req, `Sign in failed - invalid password: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "Password is invalid !!"));
  }

  logger.info(req, `Password validated successfully, generating authentication tokens - email: ${user_email}, user_id: ${user_details[0].id}`);

  let new_refresh_token = generate_token(user_details[0].id, user_details[0].user_type, process.env.REFRESH_TOKEN_KEY as string, Number(process.env.REFRESH_EXPIRY));   // Here generating json web token
  let new_access_token = generate_token(user_details[0].id, user_details[0].user_type, process.env.ACCESS_TOKEN_KEY as string, Number(process.env.ACCESS_EXPIRY));    // Here generating json web token

  let current_date_time = get_current_UTC_time();   // Getting UTC current time

  logger.info(req, `Authentication tokens generated, starting database transaction - email: ${user_email}, user_id: ${user_details[0].id}`);

  let connection: PoolConnection | null = null;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction(); // Start transaction

    logger.info(req, `Storing authentication tokens in database - email: ${user_email}, user_id: ${user_details[0].id}`);

    let newRefreshTokenId = await insert_refresh_token({ refresh_token: new_refresh_token, user_id: user_details[0].id, created_on: current_date_time, updated_on: current_date_time }, connection);   // Here we are setting refresh token in DB
    await insert_access_token({ access_token: new_access_token, refresh_token_id: newRefreshTokenId, user_id: user_details[0].id, created_on: current_date_time, updated_on: current_date_time }, connection);    // Here we are setting access token in DB

    await connection.commit();    // Commit transaction

    logger.info(req, `Database transaction committed successfully - email: ${user_email}, user_id: ${user_details[0].id}`);

    logger.info(req, `Caching access token in Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

    await set_access_token_redis(user_details[0].id, new_access_token);  // Storing access_token in redis for user sessions

    logger.info(req, `User sign in completed successfully - email: ${user_email}, user_id: ${user_details[0].id}, type: ${user_details[0].user_type}`);

    return res.status(200).json(new ApiResponse(200, { user_id: user_details[0].id, user_type: user_details[0].user_type, refresh_token: new_refresh_token, access_token: new_access_token }, "User authenticated successfully !!"));
  }
  catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(req, error, `Sign in failed during database transaction - email: ${user_email}, user_id: ${user_details[0].id}`);
    } else {
      logger.error(req, `Sign in failed during database transaction - email: ${user_email}, user_id: ${user_details[0].id}, unknown error: ${String(error)}`);
    }

    if (connection) {
      logger.info(req, `Rolling back database transaction due to sign in error - email: ${user_email}, user_id: ${user_details[0].id}`);
      await connection.rollback();    // Rollback transaction on error
    }
    if (error instanceof Error) {
      return res.status(400).json(new ApiError(400, error.message));
    } else {
      return res.status(400).json(new ApiError(400, 'Error in sign_in !!'));
    }
  }
  finally {
    if (connection) {
      connection.release();   // Released the connection finally
    }
  }
});


/**
 *
 * @name : access_token_from_refresh_token
 * @route : /auth/v1/access_token_from_refresh_token
 * @method_type : get
 * @Desc : For getting access token from refresh token
 *
 */


const access_token_from_refresh_token = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Access token refresh attempt started');

  let body = req.query;
  let required_keys = ["refresh_token"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { refresh_token } = req.query;

  logger.info(req, 'Extracting user details from refresh token');

  let user_details = get_user_from_token(refresh_token as string, "refresh_token");    // Reading user details from given refresh token

  logger.info(req, `Validating user existence and status - user_id: ${user_details.user_id}, type: ${user_details.user_type}`);

  let user_details_db = await get_user_from_id(user_details['user_id']);   // Checking whether user email exists or not
  if (user_details_db.length == 0) {
    logger.warn(req, `Access token refresh failed - user does not exist: user_id: ${user_details.user_id}`);
    return res.status(400).json(new ApiError(400, "Email does not exists !!"));
  }
  if (user_details_db[0]['is_active'] == 0) {
    logger.warn(req, `Access token refresh failed - user account is inactive: user_id: ${user_details.user_id}, email: ${user_details_db[0].user_email}`);
    return res.status(400).json(new ApiError(400, "User is not active !!"));
  }

  logger.info(req, `User validated, checking refresh token validity - user_id: ${user_details.user_id}, email: ${user_details_db[0].user_email}`);

  let find_refresh_token = await get_refresh_token_id_from_refresh_token(refresh_token as string, user_details.user_id);   // Finding refresh token exists or not in table
  if (find_refresh_token.length == 0) {
    logger.warn(req, `Access token refresh failed - refresh token does not exist: user_id: ${user_details.user_id}, email: ${user_details_db[0].user_email}`);
    return res.status(400).json(new ApiError(400, "Refresh token does not exists !!"));
  }

  logger.info(req, `Refresh token validated, generating new access token - user_id: ${user_details.user_id}, email: ${user_details_db[0].user_email}, refresh_token_id: ${find_refresh_token[0].id}`);

  let new_access_token = generate_token(user_details.user_id, user_details.user_type, process.env.ACCESS_TOKEN_KEY as string, Number(process.env.ACCESS_EXPIRY));    // Here generating json web token
  let current_date_time = get_current_UTC_time();   // Getting UTC current time

  logger.info(req, `New access token generated, updating database - user_id: ${user_details.user_id}, refresh_token_id: ${find_refresh_token[0].id}`);

  await update_access_token({ access_token: new_access_token, refresh_token_id: find_refresh_token[0].id, user_id: user_details.user_id, updated_on: current_date_time });    // Here we are setting access token relate to refresh_token_id in DB

  logger.info(req, `Database updated, caching new access token in Redis - user_id: ${user_details.user_id}`);

  await set_access_token_redis(user_details_db[0].id, new_access_token);  // Storing access_token in redis for user sessions

  logger.info(req, `Access token refresh completed successfully - user_id: ${user_details.user_id}, email: ${user_details_db[0].user_email}, type: ${user_details.user_type}`);

  return res.status(200).json(new ApiResponse(200, { user_id: user_details.user_id, refresh_token: refresh_token, access_token: new_access_token }, "Generated access token successfully !!"));
});


/**
 *
 * @name : sign_out
 * @route : /auth/v1/sign_out
 * @method_type : post
 * @Desc :
 * - For deleting refresh token
 * - For deleting access token related to refresh token
 *
 */


const sign_out = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Sign out attempt started');

  let body = req.body;
  let required_keys = ["refresh_token", "access_token"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { refresh_token, access_token } = req.body;

  logger.info(req, 'Extracting user details from refresh token for sign out');

  let user_details = get_user_from_token(refresh_token as string, "refresh_token");    // Reading user details from given refresh token

  logger.info(req, `Validating refresh token for sign out - user_id: ${user_details.user_id}, type: ${user_details.user_type}`);

  let findRefreshToken = await get_refresh_token_id_from_refresh_token(refresh_token, user_details.user_id);   // Finding refresh token exists or not in table
  if (findRefreshToken.length == 0) {
    logger.warn(req, `Sign out failed - refresh token does not exist: user_id: ${user_details.user_id}`);
    return res.status(400).json(new ApiError(400, "Refresh token does not exists !!"));
  }

  logger.info(req, `Refresh token validated, deleting tokens - user_id: ${user_details.user_id}, refresh_token_id: ${findRefreshToken[0].id}`);

  await delete_refresh_token_from_refresh_token_id(findRefreshToken[0].id);   // Deleting refresh token it will also delete accesstoken because cascade delete

  logger.info(req, `Database tokens deleted, removing access token from Redis - user_id: ${user_details.user_id}`);

  await delete_from_redis(`${user_details.user_id}:access_tokens:${access_token}`); // Removing access token from redis

  logger.info(req, `User sign out completed successfully - user_id: ${user_details.user_id}, type: ${user_details.user_type}`);

  return res.status(204).json(new ApiResponse(204, {}, "User logged out successfully !!"));
});


/**
 *
 * @name : sign_out_all
 * @route : /auth/v1/sign_out_all
 * @method_type : post
 * @Desc : For deleting refresh token and access token for a user
 *
 */


const sign_out_all = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Sign out all devices attempt started');

  let body = req.body;
  let required_keys = ["refresh_token"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { refresh_token } = req.body;

  logger.info(req, 'Extracting user details from refresh token for sign out all');

  let user_details = get_user_from_token(refresh_token, "refresh_token");    // Reading user details from given refresh token

  logger.info(req, `Validating refresh token for sign out all - user_id: ${user_details.user_id}, type: ${user_details.user_type}`);

  let findRefreshToken = await get_refresh_token_id_from_refresh_token(refresh_token, user_details.user_id);   // Finding refresh token exists or not in table
  if (findRefreshToken.length == 0) {
    logger.warn(req, `Sign out all failed - refresh token does not exist: user_id: ${user_details.user_id}`);
    return res.status(400).json(new ApiError(400, "Refresh token does not exists !!"));
  }

  logger.info(req, `Refresh token validated, deleting all user tokens - user_id: ${user_details.user_id}`);

  await delete_all_refresh_token_of_user(user_details.user_id);   // Deleting refresh token from table

  logger.info(req, `Database tokens deleted, removing all access tokens from Redis - user_id: ${user_details.user_id}`);

  await delete_multiple_from_redis(`${user_details.user_id}:access_tokens:*`); // For deleting all the access token regarding the user from redis

  logger.info(req, `User sign out all completed successfully - user_id: ${user_details.user_id}, type: ${user_details.user_type}`);

  return res.status(204).json(new ApiResponse(204, {}, "User logged out from all the devices !!"));
});


/**
 *
 * @name : forget_password
 * @route : /auth/v1/forget_password
 * @method_type : get
 * @Desc : For sending OTP to email and storing same in redis
 *
 */


const forget_password = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Forget password request started');

  let body = req.query;
  let required_keys = ["user_email"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { user_email } = req.query;

  logger.info(req, `Validating user for forget password - email: ${user_email}`);

  let user_details = await get_user_from_email(user_email as string);   // Checking whether email already exists or not
  if (user_details.length == 0) {
    logger.warn(req, `Forget password failed - email does not exist: ${user_email}`);
    return res.status(400).json(new ApiError(400, "Email does not exists !!"));
  }
  if (user_details[0]['is_active'] == 0) {
    logger.warn(req, `Forget password failed - user account is inactive: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "User is not active !!"));
  }
  if (user_details[0]['is_sso']) {
    logger.warn(req, `Forget password failed - SSO user attempted password reset: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "This is a SSO user !!"));
  }

  logger.info(req, `User validated, generating OTP for password reset - email: ${user_email}, user_id: ${user_details[0].id}`);

  let otp = generate_otp(); // Generating OTP

  logger.info(req, `OTP generated, sending email - email: ${user_email}, user_id: ${user_details[0].id}`);

  await send_email_otp(user_email as string, 'Forgot password OTP', 'Please check here is your', otp); // Sending OTP to the {user_email}

  logger.info(req, `Email sent, storing OTP in Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

  await set_forgot_pass_otp_redis(user_details[0]['id'], otp); // Storing OTP in redis

  logger.info(req, `Forget password OTP process completed successfully - email: ${user_email}, user_id: ${user_details[0].id}`);

  return res.status(204).json(new ApiResponse(204, {}, "OTP send successfully !!"));
});


/**
 *
 * @name : verify_forget_password_otp
 * @route : /auth/v1/verify_forget_password_otp
 * @method_type : get
 * @Desc : For sending OTP to email and storing same in redis
 *
 */


const verify_forget_password_otp = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'OTP verification for password reset started');

  let body = req.query;
  let required_keys = ["user_email", "otp"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { user_email, otp } = req.query;

  logger.info(req, `Validating user for OTP verification - email: ${user_email}`);

  let user_details = await get_user_from_email(user_email as string);   // Checking whether email already exists or not
  if (user_details.length == 0) {
    logger.warn(req, `OTP verification failed - email does not exist: ${user_email}`);
    return res.status(400).json(new ApiError(400, "Email does not exists !!"));
  }
  if (user_details[0]['is_active'] == 0) {
    logger.warn(req, `OTP verification failed - user account is inactive: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "User is not active !!"));
  }

  logger.info(req, `User validated, retrieving OTP from Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

  let redis_resp = await get_forgot_pass_otp_redis(user_details[0]['id']); // Getting OTP from redis db
  if (!redis_resp) {
    logger.warn(req, `OTP verification failed - OTP has expired: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "OTP has expired !!"));
  }

  if (otp !== redis_resp) {
    logger.warn(req, `OTP verification failed - incorrect OTP: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "OTP is wronge !!"));
  }

  logger.info(req, `OTP verified successfully, generating password reset secret - email: ${user_email}, user_id: ${user_details[0].id}`);

  let forgot_pass_secret = generate_secret(); // Generating secret for checking on the time of change password

  logger.info(req, `Password reset secret generated, storing in Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

  await set_forgot_pass_secret_redis(user_details[0]['id'], forgot_pass_secret); // Storing password secret in redis db with 120sec of expiry

  logger.info(req, `Secret stored, cleaning up OTP from Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

  await delete_from_redis(`${user_details[0]['id']}:forgot_password_otp`);  // Deleting OTP from redis

  logger.info(req, `OTP verification completed successfully - email: ${user_email}, user_id: ${user_details[0].id}`);

  return res.status(200).json(new ApiResponse(200, { forgot_pass_secret }, "OTP verified successfully !!"));
});


/**
 *
 * @name : change_password_with_secret
 * @route : /auth/v1/change_password_with_secret
 * @method_type : post
 * @Desc : For changing password on the basis of {forgot_pass_secret}
 *
 */


const change_password_with_secret = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Password change with secret started');

  let body = req.body;
  let required_keys = ["user_email", "new_password", "forgot_pass_secret"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { user_email, new_password, forgot_pass_secret } = req.body;

  logger.info(req, `Validating user for password change - email: ${user_email}`);

  let user_details = await get_user_from_email(user_email as string);   // Checking whether email already exists or not
  if (user_details.length == 0) {
    logger.warn(req, `Password change failed - email does not exist: ${user_email}`);
    return res.status(400).json(new ApiError(400, "Email does not exists !!"));
  }
  if (user_details[0]['is_active'] == 0) {
    logger.warn(req, `Password change failed - user account is inactive: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "User is not active !!"));
  }

  logger.info(req, `User validated, verifying password reset secret - email: ${user_email}, user_id: ${user_details[0].id}`);

  let redis_resp = await get_forgot_pass_secret_redis(user_details[0]['id']); // Getting Secret from redis db
  if (!redis_resp) {
    logger.warn(req, `Password change failed - secret has expired: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "Secret has expired !!"));
  }

  if (forgot_pass_secret !== redis_resp) {
    logger.warn(req, `Password change failed - incorrect secret: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "Secret is wronge !!"));
  }

  logger.info(req, `Secret verified, hashing new password - email: ${user_email}, user_id: ${user_details[0].id}`);

  let current_date_time = get_current_UTC_time();   // Getting UTC current time
  let hash_password = await get_bcrypt_password(new_password, process.env.PASSWORD_TOKEN_KEY as string)  // Here we are hashing the {user_password}

  logger.info(req, `Password hashed, updating database - email: ${user_email}, user_id: ${user_details[0].id}`);

  let obj = { password: hash_password, updated_on: current_date_time }
  await update_user(obj, user_details[0]['id']);   // Here we are setting new password in DB

  logger.info(req, `Password updated in database, cleaning up secret from Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

  await delete_from_redis(`${user_details[0]['id']}:forgot_password_secret`);  // Deleting Secret from redis

  logger.info(req, `Password change completed successfully - email: ${user_email}, user_id: ${user_details[0].id}`);

  return res.status(204).json(new ApiResponse(204, {}, "Password changed successfully !!"));
});


/**
 *
 * @name : sso_sign_in_token_send_google
 * @route : /auth/v1/sso_sign_in_token_send_google
 * @method_type : get
 * @Desc : For sending access token for sso login user
 *
 */


const sso_sign_in_token_send_google = async_handler(async (req: Request, res: Response) => {
  passport.authenticate('google', async (err: Error | null, user: GoogleAuthUser) => {
    if (err || !user) {
      return res.status(401).json(new ApiError(401, err?.message));
    }

    let user_info = JSON.parse(JSON.stringify(user));
    let user_details = await get_user_from_email(user_info.user_email);   // Checking whether email already exists or not
    if (user_details.length && user_details[0]['is_active'] == 0) return res.status(400).json(new ApiError(400, "User is not active !!"));  // Checking user is active or not
    if (user_details.length && user_details[0]['is_sso'] == 0) return res.status(400).json(new ApiError(400, "We already have your email registered with us"));

    if (user_details.length) {  // Handling for existing user
      let new_refresh_token = generate_token(user_details[0].id, user_details[0].user_type, process.env.REFRESH_TOKEN_KEY as string, Number(process.env.REFRESH_EXPIRY));   // Here generating json web token
      let new_access_token = generate_token(user_details[0].id, user_details[0].user_type, process.env.ACCESS_TOKEN_KEY as string, Number(process.env.ACCESS_EXPIRY));    // Here generating json web token

      let current_date_time = get_current_UTC_time();   // Getting UTC current time
      let connection: PoolConnection | null = null;
      try {
        connection = await pool.getConnection();
        await connection.beginTransaction(); // Start transaction
        let newRefreshTokenId = await insert_refresh_token({ refresh_token: new_refresh_token, user_id: user_details[0].id, created_on: current_date_time, updated_on: current_date_time }, connection);   // Here we are setting refresh token in DB
        await insert_access_token({ access_token: new_access_token, refresh_token_id: newRefreshTokenId, user_id: user_details[0].id, created_on: current_date_time, updated_on: current_date_time }, connection);    // Here we are setting access token in DB
        await connection.commit();    // Commit transaction
        await set_access_token_redis(user_details[0].id, new_access_token);  // Storing access_token in redis for user sessions

        set_auth_cookie(user_details[0].id, user_details[0].user_type, new_refresh_token, new_access_token, res);  // Setting auth cookies and also sending as response
        return res.redirect(process.env.UI_ENV ? process.env.UI_ENV as string : 'http://localhost:4200/');
      }
      catch (error: unknown) {
        if (error instanceof Error) {
          logger.error(req, error, 'SSO sign in failed during database transaction');
        } else {
          logger.error(req, `SSO sign in failed during database transaction - unknown error: ${String(error)}`);
        }

        if (connection) {
          await connection.rollback();    // Rollback transaction on error
        }
        if (error instanceof Error) {
          return res.status(400).json(new ApiError(400, error.message));
        } else {
          return res.status(400).json(new ApiError(400, 'Error in sign_in !!'));
        }
      }
      finally {
        if (connection) {
          connection.release();   // Released the connection finally
        }
      }
    }
    else {  // Handling for new users
      let connection: PoolConnection | null = null;
      try {
        connection = await pool.getConnection();
        await connection.beginTransaction(); // Start transaction

        let new_user = JSON.parse(JSON.stringify(user_info));
        let current_date_time = get_current_UTC_time();   // Getting UTC current time
        new_user.created_on = current_date_time;
        new_user.updated_on = current_date_time;
        let new_user_id = await insert_new_user(new_user, connection);   // Here we are inserting new user in DB

        let new_refresh_token = generate_token(new_user_id, new_user.user_type, process.env.REFRESH_TOKEN_KEY as string, Number(process.env.REFRESH_EXPIRY));   // Here generating json web token
        let new_access_token = generate_token(new_user_id, new_user.user_type, process.env.ACCESS_TOKEN_KEY as string, Number(process.env.ACCESS_EXPIRY));    // Here generating json web token

        let new_refresh_token_id = await insert_refresh_token({ refresh_token: new_refresh_token, user_id: new_user_id, created_on: current_date_time, updated_on: current_date_time }, connection);   // Here we are setting refresh token in DB
        await insert_access_token({ access_token: new_access_token, refresh_token_id: new_refresh_token_id, user_id: new_user_id, created_on: current_date_time, updated_on: current_date_time }, connection);    // Here we are setting access token in DB

        await connection.commit();    // Commit transaction
        await set_access_token_redis(new_user_id, new_access_token);  // Storing access_token in redis for user sessions

        set_auth_cookie(new_user_id, new_user.user_type, new_refresh_token, new_access_token, res); // Setting auth cookies and also sending as response
        return res.redirect(process.env.UI_ENV ? process.env.UI_ENV as string : 'http://localhost:4200/');
      }
      catch (err: unknown) {
        if (err instanceof Error) {
          logger.error(req, err, 'SSO registration failed during database transaction');
        } else {
          logger.error(req, `SSO registration failed during database transaction - unknown error: ${String(err)}`);
        }

        if (connection) {
          await connection.rollback();    // Rollback transaction on error
        }
        if (err instanceof Error) {
          return res.status(400).json(new ApiError(400, err.message));
        } else {
          return res.status(400).json(new ApiError(400, 'Error in registrations !!'));
        }
      }
      finally {
        if (connection) {
          connection.release();   // Released the connection finally
        }
      }
    }
  })(req, res);
});


/**
 *
 * @name : insert_permissions
 * @route : /auth/v1/insert_permissions
 * @method_type : post
 * @Desc : For updating user permissions in DB and RedisDB
 *
 */


const insert_permissions = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Insert permission request started');

  let body = req.body;
  let required_keys = ["api_route", "user_type", "method_type"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { api_route, user_type, method_type } = req.body;

  logger.info(req, `Inserting new permission - route: ${api_route}, user_type: ${user_type}, method: ${method_type}`);

  await insert_user_permission({ route: api_route, user_type, method_type }); // Inserting new permisison in DB

  logger.info(req, `Permission inserted in database, refreshing permissions cache - route: ${api_route}, user_type: ${user_type}, method: ${method_type}`);

  let user_permissions = await get_user_permission();  // Getting all the permissions from DB

  logger.info(req, `Permissions retrieved from database, updating Redis cache - total permissions: ${user_permissions.length}`);

  await set_user_permissions_redis(user_permissions); // Setting permissions in Redis

  logger.info(req, `Permission insertion completed successfully - route: ${api_route}, user_type: ${user_type}, method: ${method_type}`);

  return res.status(204).json(new ApiResponse(204, {}, "Inserted permission successfully !!"));
});


/**
 *
 * @name : refresh_permissions
 * @route : /auth/v1/refresh_permissions
 * @method_type : get
 * @Desc : For updating user permissions in DB and RedisDB
 *
 */


const refresh_permissions = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Refresh permissions request started');

  logger.info(req, 'Retrieving all permissions from database');

  let user_permissions = await get_user_permission();  // Getting all the permissions from DB

  logger.info(req, `Permissions retrieved from database, updating Redis cache - total permissions: ${user_permissions.length}`);

  await set_user_permissions_redis(user_permissions); // Setting permissions in Redis

  logger.info(req, `Permissions refresh completed successfully - total permissions cached: ${user_permissions.length}`);

  return res.status(204).json(new ApiResponse(204, {}, "Refreshed permissions successfully !!"));
});


/**
 *
 * @name : block_user
 * @route : /auth/v1/block_user
 * @method_type : put
 * @Desc : For updating user status active / inactive
 *
 */


const block_user = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Block user request started');

  let body = req.body;
  let required_keys = ["user_email"];
  let check_required_input = check_all_required_keys_data(body, required_keys, req);   // Checking whether we have got all the require inputs from request
  if (!check_required_input.status) return res.status(400).json(new ApiError(400, "Please send all the require inputs", [{ not_exists_key: check_required_input.not_exists_keys, not_exists_value: check_required_input.not_exists_value }]));
  let { user_email } = req.body;

  logger.info(req, `Validating user for blocking - email: ${user_email}`);

  let user_details = await get_user_from_email(user_email);   // Getting data on the basis of user_email
  if (user_details.length == 0) {
    logger.warn(req, `Block user failed - email does not exist: ${user_email}`);
    return res.status(400).json(new ApiError(400, "Email does not exists !!"));
  }
  if (user_details[0]['is_active'] == 0) {
    logger.warn(req, `Block user failed - user already inactive: email: ${user_email}, user_id: ${user_details[0].id}`);
    return res.status(400).json(new ApiError(400, "User is already inactive !!"));
  }

  logger.info(req, `User validated, updating user status to inactive - email: ${user_email}, user_id: ${user_details[0].id}`);

  let current_date_time = get_current_UTC_time();   // Getting UTC current time

  let obj: { is_active: 0 | 1, updated_on: string } = { is_active: 0, updated_on: current_date_time }
  await update_user(obj, user_details[0]['id']);   // Here we are setting new password in DB

  logger.info(req, `User status updated, deleting all user tokens - email: ${user_email}, user_id: ${user_details[0].id}`);

  await delete_all_refresh_token_of_user(user_details[0]['id']);   // Deleting refresh token from table

  logger.info(req, `Database tokens deleted, removing all access tokens from Redis - email: ${user_email}, user_id: ${user_details[0].id}`);

  await delete_multiple_from_redis(`${user_details[0]['id']}:access_tokens:*`); // For deleting all the access token regarding the user from redis

  logger.info(req, `User blocking completed successfully - email: ${user_email}, user_id: ${user_details[0].id}`);

  return res.status(200).json(new ApiResponse(200, { }, "User blocked successfully !!"));
});


export { register, sign_in, access_token_from_refresh_token, sign_out, sign_out_all, forget_password, verify_forget_password_otp, change_password_with_secret, sso_sign_in_token_send_google, insert_permissions, refresh_permissions, block_user };
