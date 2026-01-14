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

    // Get all events with limits
    const eventsResult = await pool
      .request()
      .query(`
        SELECT 
          event_id,
          event_code,
          event_name,
          event_type,
          max_groups_per_college,
          max_participants_per_college,
          max_accompanists_per_college,
          is_active
        FROM events
        WHERE is_active = 1
        ORDER BY event_name ASC
      `);

    const events = [];

    for (const event of eventsResult.recordset) {
      // Calculate current usage for this college
      const participantsResult = await pool
        .request()
        .input('event_id', sql.Int, event.event_id)
        .input('college_id', sql.Int, auth.college_id)
        .query(`
          SELECT COUNT(*) AS total
          FROM student_event_participation sep
          INNER JOIN students s ON sep.student_id = s.student_id
          WHERE sep.event_id = @event_id
            AND s.college_id = @college_id
            AND sep.event_type = 'participating'
        `);

      const accompanistsResult = await pool
        .request()
        .input('event_id', sql.Int, event.event_id)
        .input('college_id', sql.Int, auth.college_id)
        .query(`
          SELECT COUNT(*) AS total
          FROM accompanist_event_participation
          WHERE event_id = @event_id
            AND college_id = @college_id
        `);

      events.push({
        event_id: event.event_id,
        event_code: event.event_code,
        event_name: event.event_name,
        event_type: event.event_type,
        max_groups_per_college: event.max_groups_per_college,
        max_participants_per_college: event.max_participants_per_college,
        max_accompanists_per_college: event.max_accompanists_per_college,
        current_participants: participantsResult.recordset[0].total,
        current_accompanists: accompanistsResult.recordset[0].total,
      });
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        events,
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