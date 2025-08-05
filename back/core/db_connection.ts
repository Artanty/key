import mysql from 'mysql2/promise'
import dotenv from 'dotenv';

dotenv.config();

let pool: any

function createPool() {
  if (!pool) {
    console.log('Creatig DB pool...')
    const thisPool = mysql.createPool({
      database: process.env.DB_DATABASE,
      user: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      host: process.env.DB_HOST,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
    pool = thisPool
  }
  return pool
}

export default createPool;
