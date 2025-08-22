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
            while (this.buffer.length) {
                this.socket.write(this.buffer.shift()!);
            }
        });

        this.socket.on('error', (err: Error) => {
            this.connected = false;
            console.error('Logstash connection error:', err.message);
        });

        this.socket.on('close', () => {
            this.connected = false;
            setTimeout(() => this.socket.connect(this.port, this.host), 5044);
        });
    }

    override log(info: LogInfo, callback: () => void): void {
        setImmediate(() => this.emit('logged', info));

        const logEntry = {
            '@timestamp': info.timestamp ?? new Date().toISOString(),
            message: info.message,
            severity: info.level.toUpperCase(),
            host: hostname,
            environment: process.env.NODE_ENV ?? 'development',
            role: 'iam',
            service: 'auth-service',
            meta: {
                stack: info.stack,
                ...(typeof info.meta === 'object' && info.meta !== null ? info.meta : {}),
            },
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
function extractReqInfo(req?: Request): { user_email: string; correlation_id: string; target: string; ip: string } {
    if (!req) return { user_email: 'anonymous', correlation_id: 'N/A', target: 'N/A', ip: '0.0.0.0' };

    const user_email = 'anonymous'; // Replace with actual user extraction if available
    const correlation_id = (req.headers['nonce'] as string) ?? 'N/A';
    const target = req.originalUrl ?? req.url ?? 'N/A';

    // Normalize IP
    let ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
    ip = ip.replace(/^::ffff:/, ''); // strip IPv6 prefix

    return { user_email, correlation_id, target, ip };
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
        const { user_email, correlation_id, target, ip } = extractReqInfo(req ?? undefined);
        logger.info(message, { meta: { ...meta, user_email, correlation_id, target, ip } });
    },

    error: (req: Request | null, error: Error | string, meta: Record<string, unknown> = {}): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const { user_email, correlation_id, target, ip } = extractReqInfo(req ?? undefined);
        if (error instanceof Error) {
            logger.error(error.message, { meta: { ...meta, user_email, correlation_id, target, ip, stack: error.stack } });
        } else {
            logger.error(error, { meta: { ...meta, user_email, correlation_id, target, ip } });
        }
    },

    warn: (req: Request | null, message: string, meta: Record<string, unknown> = {}): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const { user_email, correlation_id, target, ip } = extractReqInfo(req ?? undefined);
        logger.warn(message, { meta: { ...meta, user_email, correlation_id, target, ip } });
    },

    debug: (req: Request | null, message: string, meta: Record<string, unknown> = {}): void => {
        if (!process.env.ENABLE_LOGS || process.env.ENABLE_LOGS.toLowerCase() === 'false') return;
        const { user_email, correlation_id, target, ip } = extractReqInfo(req ?? undefined);
        logger.debug(message, { meta: { ...meta, user_email, correlation_id, target, ip } });
    },
};
