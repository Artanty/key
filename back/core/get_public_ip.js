import axios from 'axios';

const getPublicIP = async () => {
    try {
      const response = await axios.get('https://api.ipify.org?format=json');
      return response.data.ip;
    } catch (error) {
      console.error('Error fetching public IP:', error);
      return 'unknown';
    }
  };

  export { getPublicIP }