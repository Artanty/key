import express, { Request, Response } from 'express';
import crypto from 'crypto';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import checkDBConnection from './core/db_check_connection'
import createPool from './core/db_connection';
import { dd } from './utils/dd';

dotenv.config();
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());

interface BackendService {
  project: string;
  url: string;
  base_key: string;
}

interface ApiToken {
  target: string;
  requester: string;
  api_key: string;
  target_url: string;
  requester_url: string;
  expires_at: Date;
}


function generateApiToken(baseKey: string, requester: string): { token: string; expiresAt: Date } {
  const expiresAt = new Date(Date.now() + 24 * 3600 * 1000);
  const token = crypto
    .createHash('sha256')
    .update(`${baseKey}-${requester}-${Date.now()}`)
    .digest('hex');
  return { token, expiresAt };
}

/**
 * Каждый бэкенд регистрируется при сборке
 * и обновляет ключ при пересборке.
 * */
// req.body {
//    "project": "@back", // идентификатор бэкенд проекта
//    "url": "http://localhost:3202" // адрес, на котором этом проект развернут, т е с которого будет отправлен запрос
//  }
 
app.post('/register', async (req: Request, res: Response) => {
  const pool = createPool();
  const connection = await pool.getConnection();

  const { project, url } = req.body;
  try {
    await connection.beginTransaction();

    // First, try to find existing entry
    const [existing] = await connection.execute(
      'SELECT id FROM backend_services WHERE project = ? AND url = ?',
      [project, url]
    );

    const baseKey = crypto
      .createHash('sha256')
      .update(`${url}-${Date.now()}-${process.env.SECRET_SALT}`)
      .digest('hex');

    if ((existing as BackendService[]).length) {
      // Update existing record
      await connection.execute(
        'UPDATE backend_services SET base_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [baseKey, existing[0].id]
      );
      dd(`Updated base_key for existing service: ${project}`);
    } else {
      // Insert new record
      await connection.execute(
        'INSERT INTO backend_services (project, url, base_key) VALUES (?, ?, ?)',
        [project, url, baseKey]
      );
      dd(`Registered new service: ${project}`);
    }
    await connection.commit();
    res.json({ baseKey });
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
});

/**
 * Перед тем, как сделать запрос на действие в другой сервис
 * получаем апи токен для этого.
 * */
// headers: {
//        'X-Project-Id': process.env.PROJECT_ID, // e.g. 'au@back' - кто будет делать запрос
//        'X-Project-Domain-Name': requesterUrl, - куда будет делать запрос
//        'X-Api-Key': process.env.BASE_KEY - ключ бэк-проекта выданный при register
//      }
app.post('/get-token', async (req: Request, res: Response) => {
  const requesterProject = req.headers['x-project-id'] as string;
  const requesterUrl = req.headers['x-project-domain-name'] as string;
  const requesterBaseKey = req.headers['x-api-key'] as string;
  const targetProject = req.body.targetProject;
  const targetUrl = req.body.targetUrl;

  // Validate all required parameters exist
  const missingParams: string[] = [];
  if (!requesterProject) missingParams.push('x-project-id header');
  if (!requesterUrl) missingParams.push('x-project-domain-name header');
  if (!requesterBaseKey) missingParams.push('x-api-key header');
  if (!targetProject) missingParams.push('body.targetProject');
  if (!targetUrl) missingParams.push('body.targetUrl');

  if (missingParams.length > 0) {
    return res.status(400).json({
      error: 'Missing required parameters',
      details: missingParams.map(p => `${p} is required`),
      code: 'MISSING_PARAMETERS'
    });
  }

  const pool = createPool();
  const connection = await pool.getConnection()
  try {
    await connection.beginTransaction();
    // Check requester registration and URL match
    const [requester] = await connection.execute(
      'SELECT url, base_key FROM backend_services WHERE project = ?',
      [requesterProject]
    );
  
    if (!(requester as BackendService[]).length || 
      requester[0].url !== requesterUrl ||
      requester[0].base_key !== requesterBaseKey
    ) {
      dd('mismatch')
      dd('requesterProject: ' + requesterProject)
      dd('[REQUEST] | [DATABASE]')
      dd('requesterUrl: ' + requesterUrl + ' | ' + requester[0].url)
      dd('requesterBaseKey: ' + requesterBaseKey + ' | ' + requester[0].base_key);
      return res.status(403).json({ error: 'Requester not registered or URL mismatch or base key rotten' });
    }  

    // Check target
    const [target] = await connection.execute(
      'SELECT url, base_key FROM backend_services WHERE project = ?',
      [targetProject]
    );
    if (!(target as BackendService[]).length || target[0].url !== targetUrl) {
      return res.status(403).json({ error: 'Invalid target or URL mismatch' });
    }

    // Check for existing token
    const [existingToken] = await connection.execute(
      `SELECT api_key, expires_at FROM api_tokens 
     WHERE target = ? AND requester = ? AND target_url = ? AND expires_at > NOW()`,
      [targetProject, requesterProject, targetUrl]
    );

    if ((existingToken as unknown as ApiToken[]).length) {
      dd('existingToken is returned of target [' + targetProject + '] goes to [' + requesterProject + ']')
      dd(existingToken)
      return res.json({ 
        apiKey: existingToken[0].api_key,
        expiresAt: existingToken[0].expires_at
      });
    }

    // Generate new token
    const { token, expiresAt } = generateApiToken(target[0].base_key, requesterProject);

    const createdKey = await connection.execute(
      `INSERT INTO api_tokens 
     (target, requester, api_key, target_url, requester_url, expires_at) 
     VALUES (?, ?, ?, ?, ?, ?)`,
      [targetProject, requesterProject, token, targetUrl, requesterUrl, expiresAt]
    );
    dd('createdKey')
    dd(createdKey)
    dd({ targetProject, requesterProject, token, targetUrl, requesterUrl, expiresAt })
    dd({ apiKey: token, expiresAt })
    await connection.commit();
    res.json({ apiKey: token, expiresAt });
  } catch (error) {
    dd('ITS ERR')
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
});

/**
 * когда в сервис приходит запрос на действие,
 * он отправляет на валидацию креды.
 * */
app.post('/validate', async (req: Request, res: Response) => {
  dd('api validate STARTED');
  const validatorProject = req.headers['x-project-id'] as string;
  const validatorUrl = req.headers['x-project-domain-name'] as string;
  const validatorBase = req.headers['x-api-key'] as string;
  const requesterProject = req.body.requesterProject as string;
  const requesterApiKey = req.body.requesterApiKey as string;
  const requesterUrl = req.body.requesterUrl as string; //todo fix

  dd('validatorProject: ' + validatorProject)
  dd('validatorUrl: ' + validatorUrl)
  dd('validatorBase: ' + validatorBase)
  dd('requesterProject: ' + requesterProject)
  dd('requesterApiKey: ' + requesterApiKey)
  dd('requesterUrl: ' + requesterUrl)

  const pool = createPool();
  const connection = await pool.getConnection()
  try {
    await connection.beginTransaction();
    
    // Validate validator project URL, base key
    const [validator] = await connection.execute(
      'SELECT url, base_key FROM backend_services WHERE project = ?',
      [validatorProject]
    );
    if (!(validator as BackendService[]).length || 
      validator[0].url !== validatorUrl || 
      validator[0].base_key !== validatorBase) {
      dd('validator Project/URL/key mismatch')
      return res.status(403).json({ valid: false, error: 'access denied' });
    }

    // Get token details
    const [token] = await connection.execute(
      `SELECT target, requester, requester_url, target_url, expires_at 
     FROM api_tokens 
     WHERE api_key = ? AND expires_at > NOW()`,
      [requesterApiKey]
    );
    dd(token)
    if (!(token as ApiToken[]).length || 
      token[0].target !== validatorProject || 
      token[0].target_url !== validatorUrl || 
      token[0].requester !== requesterProject ||
      token[0].requester_url !== requesterUrl) {
      // Log each check individually to see what's causing the issue
      let reasons: string[] = [];

      if (!(token as ApiToken[]).length) {
        reasons.push("No tokens found");
      }

      if (token[0].target !== validatorProject) {
        reasons.push(`Target mismatch: expected ${validatorProject}, got ${token[0].target}`);
      }

      if (token[0].target_url !== validatorUrl) {
        reasons.push(`Target URL mismatch: expected ${validatorUrl}, got ${token[0].target_url}`);
      }

      if (token[0].requester !== requesterProject) {
        reasons.push(`Requester mismatch: expected ${requesterProject}, got ${token[0].requester}`);
      }

      if (token[0].requester_url !== requesterUrl) {
        reasons.push(`Requester URL mismatch: expected ${requesterUrl}, got ${token[0].requester_url}`);
      }

      console.error('Validation failed:', reasons.join(', '));
      return res.status(403).json({ valid: false, error: 'Invalid or expired key' });
    }
    dd('api validate SUCCEED');
    res.json({ 
      valid: true, 
      requester: token[0].requester
    });
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
});

app.listen(PORT, () => {
  dd(`Server is running on port ${PORT}`)
  checkDBConnection()
});