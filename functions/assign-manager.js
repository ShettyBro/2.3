const sql = require('mssql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');
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
const RESEND_API_KEY = process.env.RESEND_API_KEY;

const resend = new Resend(RESEND_API_KEY);

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

  if (decoded.role !== 'principal') {
    throw new Error('Unauthorized: Principal role required');
  }

  return {
    user_id: decoded.user_id,
    role: decoded.role,
    college_id: decoded.college_id,
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

  const { manager_name, manager_email, manager_phone } = body;

  if (!manager_name || !manager_email || !manager_phone) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'manager_name, manager_email, and manager_phone are required' }),
    };
  }

  let pool;
  try {
    const auth = verifyAuth(event);
    pool = await sql.connect(dbConfig);

    // Check if Team Manager already exists for this college
    const existingResult = await pool
      .request()
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        SELECT user_id
        FROM users
        WHERE college_id = @college_id
          AND role = 'MANAGER'
          AND is_active = 1
      `);

    if (existingResult.recordset.length > 0) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Team Manager already exists for this college' }),
      };
    }

    // Check if email already exists
    const emailCheck = await pool
      .request()
      .input('email', sql.VarChar(255), manager_email)
      .query(`
        SELECT user_id
        FROM users
        WHERE email = @email
      `);

    if (emailCheck.recordset.length > 0) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Email already registered' }),
      };
    }

    // Hash default password
    const default_password = '2026@vtu';
    const password_hash = await bcrypt.hash(default_password, 12);

    // Insert Team Manager
    await pool
      .request()
      .input('full_name', sql.VarChar(255), manager_name)
      .input('email', sql.VarChar(255), manager_email)
      .input('phone', sql.VarChar(20), manager_phone)
      .input('password_hash', sql.VarChar(255), password_hash)
      .input('role', sql.VarChar(50), 'MANAGER')
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        INSERT INTO users (full_name, email, phone, password_hash, role, college_id, is_active)
        VALUES (@full_name, @email, @phone, @password_hash, @role, @college_id, 1)
      `);

    // Send email with credentials
    try {
      await resend.emails.send({
        from: 'VTU Fest 2026 <noreply@vtufest2026.acharyahabba.com>',
        to: manager_email,
        subject: 'You have been assigned as Team Manager - VTU Fest 2026',
        html: `
          <h2>Welcome to VTU Fest 2026!</h2>
          <p>Dear ${manager_name},</p>
          <p>You have been assigned as <strong>Team Manager</strong> for your college.</p>
          <h3>Your Login Credentials:</h3>
          <ul>
            <li><strong>Email:</strong> ${manager_email}</li>
            <li><strong>Password:</strong> ${default_password}</li>
          </ul>
          <p><a href="https://vtufest2026.acharyahabba.com/">Login here</a></p>
          <p><strong>IMPORTANT:</strong> You must change your password on first login.</p>
          <p>Best regards,<br>VTU Fest Team</p>
        `,
      });
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      // Continue even if email fails
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Team Manager assigned successfully. Email sent with login credentials.',
      }),
    };
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