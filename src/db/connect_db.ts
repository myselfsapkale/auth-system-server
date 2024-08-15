import mysql, { Pool, PoolConnection } from 'mysql2/promise';
import { Redis } from 'ioredis';
import dotenv from 'dotenv';

dotenv.config({ path: './.env' });


// MySQL database connection options from environment variables
const my_sql_db_config = {
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USR,
  port: process.env.MYSQL_PORT ? parseInt(process.env.MYSQL_PORT) : undefined,
  database: process.env.MYSQL_DATABASE,
  password: process.env.MYSQL_PASSWORD,
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10,
  idleTimeout: 60000,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
};


// Creating a MySQL connection pool
const pool: Pool = mysql.createPool(my_sql_db_config);


// Redis database connection options from environment variables
const redis_db_config = {
  port: Number(process.env.REDIS_PORT),
  host: process.env.REDIS_HOST,
  password: process.env.REDIS_PASSWORD,
  db: Number(process.env.REDIS_DB)
}


// Creating a redis connection
const redis_cli: Redis = new Redis(redis_db_config);


// Function to establish database connection (MySQL && Redis)
const connect_db: Promise<void> = new Promise(async (res, rej) => {
  try {
    const connection: PoolConnection = await pool.getConnection();  // Checking connection of MySQL
    await redis_cli.ping();   // Checking connection of redis
    connection.release();
    res();
  }
  catch (err) {
    rej(err);
  }
});


export { connect_db, pool, redis_cli };