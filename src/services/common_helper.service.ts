import { get_count_of_all_permissions } from "../utils/redis_handler";
import { TokenUserDetail } from "../interfaces/auth.interface";
import jwt from "jsonwebtoken";
import logger from '../utils/elk_logger';
import type { Request } from 'express';


/**
 *
 * @name : check_permissions_exists
 * @Desc : For authenticate user with access token
 *
 */


async function checkPermissionsExists(): Promise<boolean> {
    const methods = ["get", "post", "put", "patch", "delete"];
    const userTypes = ["admin", "user"];

    // Function to check permissions for a single user type and method
    const checkPermissionsForUserType = async (userType: string) => {
        for (const method of methods) {
            if (await get_count_of_all_permissions(userType, method)) {
                return true;
            }
        }
        return false;
    };

    // Check permissions for all user types
    const results = await Promise.all(userTypes.map(checkPermissionsForUserType));

    // Return true if any user type has permissions
    return results.some(hasPermission => hasPermission);
}


/**
 *
 * @name - get_current_UTC_time
 * @desc - It will return current UTC time
 *
 */


function get_current_UTC_time() {
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = ('0' + (now.getUTCMonth() + 1)).slice(-2);
    const day = ('0' + now.getUTCDate()).slice(-2);
    const hours = ('0' + now.getUTCHours()).slice(-2);
    const minutes = ('0' + now.getUTCMinutes()).slice(-2);
    const seconds = ('0' + now.getUTCSeconds()).slice(-2);

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}


/**
 *
 * @name - check_all_required_keys_data
 * @desc -
 * - It will check whether all {data} has all the require keys and it should not be empty as well
 * - It will return status and the keys which are missing or data is not there
 *
 */


function check_all_required_keys_data(data: any, required_keys: string[], req: Request): { status: boolean, not_exists_keys: string[], not_exists_value: string[] } {
    let not_exists_keys: string[] = [], not_exists_value: string[] = [];
    required_keys.map((p: string) => {
        if (!data.hasOwnProperty(p)) not_exists_keys.push(p);     // If kes does not exists in object itself then we will put it in {notExistsKeys}
        if (!data[p]) not_exists_value.push(p);     // If key does not have any data then we will put it in {notExistsValue}
    });
    if (not_exists_keys.length > 0 || not_exists_value.length > 0) {
        const providedKeys = Object.keys(data || {}).join(', ');
        const missingKeys = not_exists_keys.join(', ');
        const emptyKeys = not_exists_value.join(', ');
        logger.error(req, `Required keys validation failed - required: [${required_keys.join(', ')}], missing: [${missingKeys}], empty: [${emptyKeys}], provided: [${providedKeys}]`);
        return { status: false, not_exists_keys: not_exists_keys, not_exists_value: not_exists_value };
    }
    else return { status: true, not_exists_keys: [], not_exists_value: [] };
}


/**
 *
 * @name : get_user_from_token
 * @Desc : For getting user details from token
 *
 */


function get_user_from_token(token: string, token_type: 'refresh_token' | 'access_token'): TokenUserDetail {
    let token_key = token_type === "refresh_token" ? process.env.REFRESH_TOKEN_KEY as string : process.env.ACCESS_TOKEN_KEY as string;
    let data = jwt.verify(token, token_key) as TokenUserDetail;
    return data;
}

export { checkPermissionsExists, get_current_UTC_time, check_all_required_keys_data, get_user_from_token };
