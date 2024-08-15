import { Request, Response, NextFunction, RequestHandler } from 'express';
import { ApiError } from './api_response';


/**
 * 
 * @name : async_handler
 * @Desc : 
 * - This method is a middleware method if we get any error inside it then it will return error response
 * - Every controller has to go from this check
 * 
 */


const async_handler = (request_handler: RequestHandler) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(request_handler(req, res, next)).catch((err) => res.status(500).json(new ApiError(500, 'Something went wrong !!', err)) );
    };
};


export { async_handler };