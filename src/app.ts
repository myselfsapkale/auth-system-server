import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import router from './routes/router'


// Initialize Express application
const app: Express = express();


// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*', // Adjust as needed for your CORS configuration
  credentials: true
}));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));
app.use(cookieParser());


// Routes
app.use(router);


// Example route
app.get('/', (req: Request, res: Response) => {
  res.send('Welcome to my TypeScript Express application');
});


export { app };