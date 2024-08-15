class ApiError extends Error {
    public status_code: number;
    public message: string;
    public data: any | null;
    public success: boolean;
    public errors: any[];

    constructor(
        statusCode: number,
        message: string = "Something went wrong",
        errors: any[] = [],
        stack: string = ""
    ) {
        super();
        this.status_code = statusCode;
        this.message = message;
        this.data = null;
        this.success = false;
        this.errors = errors;

        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}


class ApiResponse {
    public statusCode: number;
    public data: any;
    public message: string;
    public success: boolean;

    constructor(statusCode: number, data: any, message: string = "Success") {
        this.statusCode = statusCode;
        this.data = data;
        this.message = message;
        this.success = statusCode < 400;
    }
}


export { ApiError, ApiResponse };