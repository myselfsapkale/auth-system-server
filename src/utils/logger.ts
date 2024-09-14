import { Request, Response, NextFunction } from 'express';
import { async_handler } from './async_handler';
import { insert_logs_in_sql } from '../model/auth.model';


// Extend the Express Request interface to include a custom startTime property
interface CustomRequest extends Request {
    startTime?: number;
}


/**
 * Middleware to log detailed information about requests and responses.
 * Logs request and response details including request body, response body,
 * response time (in milliseconds), and status codes. Logs only when status codes are 400 or higher.
 */
const custom_logs = async_handler(async (req: CustomRequest, res: Response, next: NextFunction) => {
    req.startTime = Date.now();
    const originalSend = res.send;
    let responseBody: any = ''; // Variable to store the response body

    res.send = function (body: any) {
        responseBody = body; // Capture the response body
        return originalSend.call(this, body);
    };

    next();

    res.on('finish', async () => {
        const method: string = req.method;
        const url_path = req.path; // Get the URL path
        const status = res.statusCode; // Get the HTTP status code
        const correlation_id = req.headers['nonce'] as string || 'N/A'; // Extract correlation ID from headers

        const response_time = Date.now() - (req.startTime || Date.now());
        const body_params = req.body ? req.body : req.query;
        if (body_params.hasOwnProperty('password')) body_params.password = '*';
        if (body_params.hasOwnProperty('access_token')) body_params.access_token = '*';
        if (body_params.hasOwnProperty('refresh_token')) body_params.refresh_token = '*';
        if (body_params.hasOwnProperty('token')) body_params.token = '*';

        
        const logObject = {
            method_type: method,
            url: url_path,
            status: status,
            correlation_id: correlation_id,
            response_time: response_time, // Log response time in milliseconds
            request_body: JSON.stringify(body_params) || 'N/A', // Include request body or query parameters
            response_body: typeof (responseBody) === 'string' ? responseBody || 'N/A' : JSON.stringify(responseBody) || 'N/A', // Include response body
        };

        if (true) { // Log only if status code is 400 or higher
            await insert_logs_in_sql(logObject).catch(err => {
                console.error(`Failed to insert log into MySQL: ${err}`);
            });
        }
    });
});


export { custom_logs };




/**
 * @Note - This below code is for future reference if we want to add {winston} or {morgan}
 *       - For now we are not using thems
 */




// import { createLogger, format, transports, Logger } from 'winston';
// import morgan, { StreamOptions } from 'morgan';
// import { insert_logs_in_sql } from '../model/auth.model';
// import { Request } from 'express';

// // Destructure format methods from 'winston'
// const { combine, timestamp, json, colorize, printf } = format;


// // Define a custom format for console logging with colors
// const log_format = printf(({ level, message, timestamp }) => {
//     return `${level}: ${message}`;
// });


// // Create a Winston logger
// const logger: Logger = createLogger({
//     level: 'info',
//     format: combine(timestamp(), json()),
//     transports: [
//         // new transports.Console({
//         //     format: combine(colorize(), log_format),
//         // }),
//         new transports.File({ filename: './src/utils/app.log' }),
//     ],
// });


// // Define the format for Morgan logging
// const morgan_format = ':method :url :status :req[Nonce] :response-time :request-body';
// const morgan_stream: StreamOptions = {
//     write: async (message: string) => {
//         const [method, url, status, correlation_id, response_time, request_body] = message.trim().split(' ');
//         let obj = {
//             method_type: method,
//             url: url,
//             status: status,
//             correlation_id: correlation_id,
//             response_time: parseFloat(response_time),
//             request_body
//         }
//         logger.info(JSON.stringify(obj))

//         if (Number(status) >= 400 && process.env.NODE_ENV == "production") { // Only log status code 400 or more
//             await insert_logs_in_sql(obj).catch(err => {    // Inserting logs into MySQL database for tracking
//                 logger.error(`Failed to insert log into MySQL: ${err}`);
//             });
//         }
//     }
// };


// // For reading request body in morgan
// morgan.token('request-body', (req: Request) => {
//     let data = req.body ? req.body : req.query;
//     data = data ? data : req.params;
//     if (data) {
//         if (data.hasOwnProperty('password')) data.password = '*';
//         if (data.hasOwnProperty('access_token')) data.access_token = '*';
//         if (data.hasOwnProperty('refresh_token')) data.refresh_token = '*';
//         if (data.hasOwnProperty('token')) data.token = '*';
//     }
//     return JSON.stringify(data) || 'N/A';
// });


// // Create the Morgan middleware instance
// const morgan_middleware = morgan(morgan_format, { stream: morgan_stream });


// // Export the Morgan middleware
// export { morgan_middleware as morgan_obj, logger };