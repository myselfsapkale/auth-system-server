import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import router from './routes/router'
import { custom_logs } from './utils/logger';


// Initialize Express application
const app: Express = express();


// Middleware
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));
app.use(cookieParser());
app.use(custom_logs); // Added logs here


// Routes
app.use(router);


// Example route
app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to my TypeScript Express application');
});


export { app };