const sql = require('mssql');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { BlobServiceClient, generateBlobSASQueryParameters, BlobSASPermissions, StorageSharedKeyCredential } = require('@azure/storage-blob');
require('dotenv').config();

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

const JWT_SECRET = process.env.JWT_SECRET;
const AZURE_STORAGE_ACCOUNT_NAME = process.env.AZURE_STORAGE_ACCOUNT_NAME;
const AZURE_STORAGE_ACCOUNT_KEY = process.env.AZURE_STORAGE_ACCOUNT_KEY;
const CONTAINER_NAME = 'student-documents';

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const verifyAuth = (event) => {
  const authHeader = event.headers.authorization || event.headers.Authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Missing or invalid Authorization header');
  }

  const token = authHeader.substring(7);
  const decoded = jwt.verify(token, JWT_SECRET);

  if (decoded.role !== 'manager') {
    throw new Error('Unauthorized: Manager role required');
  }

  return {
    user_id: decoded.user_id,
    full_name: decoded.full_name,
    role: decoded.role,
    college_id: decoded.college_id,
  };
};

const generateSASUrl = (blobPath) => {
  const sharedKeyCredential = new StorageSharedKeyCredential(
    AZURE_STORAGE_ACCOUNT_NAME,
    AZURE_STORAGE_ACCOUNT_KEY
  );

  const blobServiceClient = new BlobServiceClient(
    `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net`,
    sharedKeyCredential
  );

  const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
  const blobClient = containerClient.getBlobClient(blobPath);

  const expiresOn = new Date(Date.now() + 25 * 60 * 1000);

  const sasToken = generateBlobSASQueryParameters(
    {
      containerName: CONTAINER_NAME,
      blobName: blobPath,
      permissions: BlobSASPermissions.parse('w'),
      expiresOn,
    },
    sharedKeyCredential
  ).toString();

  return `${blobClient.url}?${sasToken}`;
};

// ============================================================================
// ACTION: check_profile_status
// ============================================================================
const checkProfileStatus = async (pool, auth) => {
  // Check if manager exists in accompanists table with is_team_manager = 1
  const result = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT accompanist_id
      FROM accompanists
      WHERE college_id = @college_id
        AND is_team_manager = 1
    `);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      profile_completed: result.recordset.length > 0,
    }),
  };
};

// ============================================================================
// ACTION: init_manager_profile
// ============================================================================
const initManagerProfile = async (pool, auth) => {
  // Check if profile already completed
  const existingResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT accompanist_id
      FROM accompanists
      WHERE college_id = @college_id
        AND is_team_manager = 1
    `);

  if (existingResult.recordset.length > 0) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Profile already completed' }),
    };
  }

  // Get college_code
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code
      FROM colleges
      WHERE college_id = @college_id
    `);

  if (collegeResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ error: 'College not found' }),
    };
  }

  const college_code = collegeResult.recordset[0].college_code;

  // Generate session_id
  const session_id = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 25 * 60 * 1000);

  // Store session
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .input('full_name', sql.VarChar(255), auth.full_name)
    .input('expires_at', sql.DateTime2, expires_at)
    .query(`
      INSERT INTO accompanist_sessions (
        session_id, college_id, full_name, phone, email, accompanist_type, student_id, assigned_events, expires_at
      )
      VALUES (@session_id, @college_id, @full_name, 'PENDING', 'PENDING', 'faculty', NULL, '[]', @expires_at)
    `);

  // Generate SAS URLs
  const blobBasePath = `${college_code}/manager-${auth.full_name.replace(/\s+/g, '_')}`;
  const upload_urls = {
    passport_photo: generateSASUrl(`${blobBasePath}/passport_photo`),
    college_id_card: generateSASUrl(`${blobBasePath}/college_id_card`),
    aadhaar_card: generateSASUrl(`${blobBasePath}/aadhaar_card`),
  };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      session_id,
      upload_urls,
      expires_at: expires_at.toISOString(),
    }),
  };
};

// ============================================================================
// ACTION: finalize_manager_profile
// ============================================================================
const finalizeManagerProfile = async (pool, auth, body) => {
  const { session_id } = body;

  if (!session_id) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'session_id is required' }),
    };
  }

  // Validate session
  const sessionResult = await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT expires_at
      FROM accompanist_sessions
      WHERE session_id = @session_id AND college_id = @college_id
    `);

  if (sessionResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ error: 'Invalid or expired session' }),
    };
  }

  const expires_at = new Date(sessionResult.recordset[0].expires_at);

  if (Date.now() > expires_at.getTime()) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Session expired. Please restart.' }),
    };
  }

  // Get college_code and user phone
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code
      FROM colleges
      WHERE college_id = @college_id
    `);

  const userResult = await pool
    .request()
    .input('user_id', sql.Int, auth.user_id)
    .query(`
      SELECT phone, email
      FROM users
      WHERE user_id = @user_id
    `);

  const college_code = collegeResult.recordset[0].college_code;
  const user_phone = userResult.recordset[0].phone || 'N/A';
  const user_email = userResult.recordset[0].email;

  // Insert manager as accompanist with is_team_manager = 1
  const blobBasePath = `${college_code}/manager-${auth.full_name.replace(/\s+/g, '_')}`;
  
  await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .input('full_name', sql.VarChar(255), auth.full_name)
    .input('phone', sql.VarChar(20), user_phone)
    .input('email', sql.VarChar(255), user_email)
    .input('accompanist_type', sql.VarChar(20), 'faculty')
    .input('passport_photo_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${blobBasePath}/passport_photo`)
    .input('id_proof_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${blobBasePath}/aadhaar_card`)
    .input('is_team_manager', sql.Bit, 1)
    .query(`
      INSERT INTO accompanists (
        college_id, full_name, phone, email, accompanist_type, passport_photo_url, id_proof_url, is_team_manager
      )
      VALUES (@college_id, @full_name, @phone, @email, @accompanist_type, @passport_photo_url, @id_proof_url, @is_team_manager)
    `);

  // Delete session
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .query(`DELETE FROM accompanist_sessions WHERE session_id = @session_id`);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Profile completed successfully. You are now counted in the 45-person quota.',
    }),
  };
};

// ============================================================================
// MAIN HANDLER
// ============================================================================
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid JSON body' }),
    };
  }

  const { action } = body;

  if (!action) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'action is required' }),
    };
  }

  let pool;
  try {
    const auth = verifyAuth(event);
    pool = await sql.connect(dbConfig);

    if (action === 'check_profile_status') {
      return await checkProfileStatus(pool, auth);
    } else if (action === 'init_manager_profile') {
      return await initManagerProfile(pool, auth);
    } else if (action === 'finalize_manager_profile') {
      return await finalizeManagerProfile(pool, auth, body);
    } else {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid action' }),
      };
    }
  } catch (error) {
    console.error('Error:', error);

    if (error.message.includes('Authorization') || error.message.includes('Unauthorized')) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: error.message }),
      };
    }

    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Internal server error',
        details: error.message,
      }),
    };
  } finally {
    if (pool) {
      await pool.close();
    }
  }
};