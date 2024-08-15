import { PoolConnection, ResultSetHeader, RowDataPacket } from 'mysql2/promise';
import { pool } from "../db/connect_db";
import { UserType } from "../interfaces/auth.interface";


/**
 * 
 * @name : get_user_from_email
 * @Desc : For getting user's details on the basis of email
 * 
 */


async function get_user_from_email(user_email: string): Promise<RowDataPacket[]> {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM users WHERE user_email = ?', [user_email]);
    return rows;
}


/**
 * 
 * @name : get_user_from_id
 * @Desc : For getting user's details on the basis of user_id
 * 
 */


async function get_user_from_id(user_id: number): Promise<RowDataPacket[]> {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM users WHERE id = ?', [user_id]);
    return rows;
}


/**
 * 
 * @name : check_phone_exists
 * @Desc : For checking phone number exists in table
 * 
 */


async function check_phone_exists(user_phone: string): Promise<boolean> {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM users WHERE user_phone = ?', [user_phone]);
    return !!rows;
}


/**
 * 
 * @name : insert_new_user
 * @Desc : 
 * - For inserting new user into DB
 * - This is a transition query, so it has a {connection} as a parameter, which can be used if we are using it in transitions
 * 
 */


async function insert_new_user(newUser: UserType, connection: PoolConnection): Promise<number> {
    const [rows] = await connection.query<ResultSetHeader>('INSERT INTO users SET ?', newUser);
    return rows.insertId;
}


/**
 * 
 * @name : insert_refresh_token
 * @Desc : 
 * - For inserting new refresh token into DB
 * - This is a transition query, so it has a {connection} as a parameter, which can be used if we are using it in transitions
 * 
 */


async function insert_refresh_token(new_refresh_token: { refresh_token: string, user_id: number, created_on: string, updated_on: string }, connection: PoolConnection): Promise<number> {
    const [rows] = await connection.query<ResultSetHeader>('INSERT INTO auth_refresh_token SET ?', new_refresh_token);
    return rows.insertId;
}


/**
 * 
 * @name : insert_access_token
 * @Desc : For inserting new access token into DB
 * 
 */


async function insert_access_token(new_access_token: { access_token: string, refresh_token_id: number, user_id: number, created_on: string, updated_on: string }, connection: PoolConnection): Promise<number> {
    const [rows] = await connection.query<ResultSetHeader>('INSERT INTO auth_access_token SET ?', new_access_token);
    return rows.insertId;
}


/**
 * 
 * @name : update_access_token
 * @Desc : 
 * - For updating new access token into DB
 * - We will use it for replacing expired access token with new access token
 * 
 */


async function update_access_token(new_access_token: { access_token: string, refresh_token_id: number, user_id: number, updated_on: string }): Promise<number> {
    const [rows] = await pool.query<ResultSetHeader>('UPDATE auth_access_token SET ? WHERE refresh_token_id = ?', [new_access_token, new_access_token.refresh_token_id]);
    return rows.insertId;
}


/**
 * 
 * @name : get_refresh_token_id_from_refresh_token
 * @Desc : For getting refresh_token_id from refresh token
 * 
 */


async function get_refresh_token_id_from_refresh_token(refresh_token: string, user_id: number): Promise<RowDataPacket[]> {
    const [rows] = await pool.query<RowDataPacket[]>('SELECT * FROM auth_refresh_token WHERE refresh_token = ? AND user_id = ?', [refresh_token, user_id]);
    return rows;
}


/**
 * 
 * @name : delete_all_refresh_token_of_user
 * @Desc : For deleting all refresh_token_id from refresh token it will also delete all access_token also from DB because of cascade
 * 
 */


async function delete_all_refresh_token_of_user(user_id: number): Promise<RowDataPacket[]> {
    const [rows] = await pool.query<RowDataPacket[]>('DELETE FROM auth_refresh_token WHERE user_id = ?', [user_id]);
    return rows;
}


/**
 * 
 * @name : delete_refresh_token_from_refresh_token_id
 * @Desc : For deleting refresh_token_id from refresh token on the basis of refresh_token
 * 
 */


async function delete_refresh_token_from_refresh_token_id(refresh_token_id: number): Promise<ResultSetHeader> {
    const [rows] = await pool.query<ResultSetHeader>('DELETE FROM auth_refresh_token WHERE id = ?', [refresh_token_id]);
    return rows;
}


/**
 * 
 * @name : update_user_password
 * @Desc : For updating user password
 * 
 */


async function update_user_password(user_update_data: { password: string, updated_on: string }, user_id: number): Promise<number> {
    const [rows] = await pool.query<ResultSetHeader>('UPDATE users SET ? WHERE id = ?', [user_update_data, user_id]);
    return rows.insertId;
}


export { get_user_from_email, get_user_from_id, check_phone_exists, insert_new_user, insert_refresh_token, insert_access_token, update_access_token, get_refresh_token_id_from_refresh_token, delete_refresh_token_from_refresh_token_id, delete_all_refresh_token_of_user, update_user_password };