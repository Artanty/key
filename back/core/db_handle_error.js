import { getPublicIP } from './get_public_ip.js'

const handleDatabaseError = async (error, logger) => {
    logger.error('Database error:', error);

    if (error.code === 'ER_NO_SUCH_TABLE') {
      logger.error('Table entries doesn\'t exist');
      return;
    }
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || /ETIMEDOUT/.test(error.message || '')) {
      const publicIP = await getPublicIP();
      logger.error(`Database connection refused or timed out. Check that the IP of this backend is added to permitted: ${publicIP}`);
      return;
    }
    logger.error(error.message);
  };

  export { handleDatabaseError }
