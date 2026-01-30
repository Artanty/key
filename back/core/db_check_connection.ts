import createPool from './db_connection'

async function checkDBConnection() {
  console.log('Checking DB connection...')
  console.log('database: ' + process.env.DB_DATABASE)
  try {
    const pool = createPool()
    const [rows] = await pool.query(`SELECT COUNT(*) AS table_count FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = "${process.env.DB_DATABASE}";`);
    console.log(`Database ${process.env.DB_DATABASE} with ${rows[0]?.table_count} tables is successfully connected.`);
  } catch (error) {
    console.log('DB connection error: ')
    console.log(error)
  }
}

export default checkDBConnection;