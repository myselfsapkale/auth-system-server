import { createLogger, format, transports, Logger } from 'winston';
import TransportStream, { TransportStreamOptions } from 'winston-transport';
import net from 'net';
import os from 'os';
import type { Request } from 'express';

interface LogInfo {
    level: string;
    message: string;
    timestamp?: string;
    stack?: string;
    meta?: Record<string, unknown>;
    [key: string]: unknown;
}

interface LogstashTransportOptions extends TransportStreamOptions {
    host: string;
    port: number;
}

const hostname = os.hostname();

/**
 * Custom Winston transport sending logs over TCP to Logstash
 */
class LogstashTcpTransport extends TransportStream {
    private socket: net.Socket;
    private host: string;
    private port: number;
    private connected = false;
    private buffer: string[] = [];

    constructor(opts: LogstashTransportOptions) {
        super(opts);
        this.host = opts.host;
        this.port = opts.port;
        this.socket = new net.Socket();

        this.socket.connect(this.port, this.host);

        this.socket.on('connect', () => {
            this.connected = true;
            console.log('DEBUG: Connected to Logstash'); // Debug
            while (this.buffer.length) {
                this.socket.write(this.buffer.shift()!);
            }
        });

        this.socket.on('error', (err: Error) => {
            this.connected = false;
            console.log('DEBUG: Logstash connection error:', err.message); // Debug
        });

        this.socket.on('close', () => {
            this.connected = false;
            console.log('DEBUG: Logstash connection closed, reconnecting...'); // Debug
            setTimeout(() => this.socket.connect(this.port, this.host), 5044);
        });
    }

    override log(info: LogInfo, callback: () => void): void {
        setImmediate(() => this.emit('logged', info));

        const logEntry = {
            message: info.message,
            severity: (info.level || 'info').toString().toUpperCase(),
            ip: (info.meta as any)?.ip,
            correlation_id: (info.meta as any)?.correlation_id,
            timestamp: new Date().toISOString(),
            token_user_id: (info.meta as any)?.token_user_id,
            token_user_type: (info.meta as any)?.token_user_type,
            target_path: (info.meta as any)?.target,
            method: (info.meta as any)?.method,
            ...(info.stack && { stack: info.stack })
        };

        const json = JSON.stringify(logEntry) + '\n';

        if (this.connected) {
            this.socket.write(json);
        } else {
            this.buffer.push(json);
        }

        callback();
    }
}

/**
 * Extract user info and request metadata
 */
function extractReqInfo(req?: Request): {
    token_user_id: string;
    token_user_type: string;
    correlation_id: string;
    target: string;
    ip: string;
    method: string;
} {
    if (!req) return {
        token_user_id: 'anonymous',
        token_user_type: 'anonymous',
        correlation_id: 'N/A',
        target: 'N/A',
        ip: '0.0.0.0',
        method: 'N/A'
    };

    const token_user_id = req?.body?.token_user_id ?? 'anonymous';
    const token_user_type = req?.body?.token_user_type ?? 'anonymous';
    const correlation_id = (req.headers['nonce'] as string) ?? 'N/A';
    const target = req.originalUrl ?? req.url ?? 'N/A';
    const method = req.method ?? 'N/A';

    // Normalize IP
    let ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
    ip = ip.replace(/^::ffff:/, ''); // strip IPv6 prefix

    return {
        token_user_id,
        token_user_type,
        correlation_id,
        target,
        ip,
        method
    };
}

/**
 * Winston logger instance
 */
const logger: Logger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp(),
        format.errors({ stack: true }),
        format.json()
    ),
    transports: [
        new LogstashTcpTransport({ host: 'logstash', port: 5044 }),
        new transports.Console({ format: format.json() }) // JSON for console too
    ],
});

export default {
    info: (req: Request | null, message: string, meta: Record<string, unknown> = {}): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const reqInfo = extractReqInfo(req ?? undefined);
        logger.info(message, { meta: { ...meta, ...reqInfo } });
    },

    error: (req: Request | null, error: Error | string, message?: string): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const reqInfo = extractReqInfo(req ?? undefined);
        if (error instanceof Error) {
            // Create a comprehensive error message with stack trace info
            const errorMessage = message 
                ? `${message} - Error: ${error.message} (${error.constructor.name})`
                : `${error.message} (${error.constructor.name})`;
            logger.error(errorMessage, { 
                meta: { ...reqInfo, stack: error.stack }
            });
        } else {
            // For string errors, use the message or the error string itself
            logger.error(message || error, { meta: { ...reqInfo } });
        }
    },

    warn: (req: Request | null, message: string, meta: Record<string, unknown> = {}): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const reqInfo = extractReqInfo(req ?? undefined);
        logger.warn(message, { meta: { ...meta, ...reqInfo } });
    },

    debug: (req: Request | null, message: string, meta: Record<string, unknown> = {}): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const reqInfo = extractReqInfo(req ?? undefined);
        logger.debug(message, { meta: { ...meta, ...reqInfo } });
    },
};
