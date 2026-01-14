const sql = require('mssql');
const jwt = require('jsonwebtoken');
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

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const verifyAuth = (event) => {
 try {
      const authHeader = event.headers.authorization || event.headers.Authorization;
         
         if (!authHeader || !authHeader.startsWith("Bearer ")) {
           return {
             statusCode: 401,
             headers,
             body: JSON.stringify({
               success: false,
               message: "Token expired. Redirecting to login...",
               redirect: "https://vtufest2026.acharyahabba.com/",
             }),
           };
         }
     
         const token = authHeader.substring(7);
         let decoded;
     
         try {
           decoded = jwt.verify(token, JWT_SECRET);
         } catch (err) {
           return {
             statusCode: 401,
             headers,
             body: JSON.stringify({
               success: false,
               message: "Token expired. Redirecting to login...",
               redirect: "https://vtufest2026.acharyahabba.com/",
             }),
           };
         }
       const role = decoded.role;
 
 
     if (decoded.role !== 'PRINCIPAL' && decoded.role !== 'MANAGER') {
       throw new Error('Unauthorized: Principal or Manager role required');
     }
     const auth = {
       user_id: decoded.user_id,
       college_id: decoded.college_id,
       role: decoded.role,
     };
      return auth;
    } catch (error) {
      throw error;
    }
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

  let pool;
  try {
    const auth = verifyAuth(event);
    pool = await sql.connect(dbConfig);

    // Get college lock status and payment status
    const result = await pool
      .request()
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        SELECT 
          c.is_final_approved,
          c.final_approved_at,
          c.college_code,
          c.college_name,
          pr.status AS payment_status,
          pr.uploaded_at AS payment_uploaded_at,
          pr.admin_remarks AS payment_remarks
        FROM colleges c
        LEFT JOIN payment_receipts pr ON c.college_id = pr.college_id
        WHERE c.college_id = @college_id
      `);

    if (result.recordset.length === 0) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({ error: 'College not found' }),
      };
    }

    const data = result.recordset[0];

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        is_locked: data.is_final_approved === 1,
        final_approved_at: data.final_approved_at,
        college_code: data.college_code,
        college_name: data.college_name,
        payment_status: data.payment_status,
        payment_uploaded_at: data.payment_uploaded_at,
        payment_remarks: data.payment_remarks,
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