import createPool from './db_connection'
import { handleDatabaseError } from './db_handle_error.ts'
import { logger } from '../utils/logger.ts'


async function checkDBConnection() {
  console.log('Checking DB connection...')
  console.log('database: ' + process.env.DB_DATABASE)
  try {
    const pool = createPool()
    const [rows] = await pool.query(`SELECT COUNT(*) AS table_count FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = "${process.env.DB_DATABASE}";`);
    console.log(`Database ${process.env.DB_DATABASE} with ${rows[0]?.table_count} tables is successfully connected.`);
  } catch (error) {
    return handleDatabaseError(error, logger)
  }
}

export default checkDBConnection;