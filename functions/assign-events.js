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

// ============================================================================
// EVENT SLUG TO TABLE MAPPING (25 EVENTS)
// ============================================================================
const EVENT_TABLES = {
  'mime': 'event_mime',
  'mimicry': 'event_mimicry',
  'one_act_play': 'event_one_act_play',
  'skits': 'event_skits',
  'debate': 'event_debate',
  'elocution': 'event_elocution',
  'quiz': 'event_quiz',
  'cartooning': 'event_cartooning',
  'clay_modelling': 'event_clay_modelling',
  'collage_making': 'event_collage_making',
  'installation': 'event_installation',
  'on_spot_painting': 'event_on_spot_painting',
  'poster_making': 'event_poster_making',
  'rangoli': 'event_rangoli',
  'spot_photography': 'event_spot_photography',
  'classical_vocal_solo': 'event_classical_vocal_solo',
  'classical_instrumental_percussion': 'event_classical_instrumental_percussion',
  'classical_instrumental_non_percussion': 'event_classical_instrumental_non_percussion',
  'light_vocal_solo': 'event_light_vocal_solo',
  'western_vocal_solo': 'event_western_vocal_solo',
  'group_song_indian': 'event_group_song_indian',
  'group_song_western': 'event_group_song_western',
  'folk_orchestra': 'event_folk_orchestra',
  'folk_tribal_dance': 'event_folk_tribal_dance',
  'classical_dance_solo': 'event_classical_dance_solo',
};

// ============================================================================
// AUTH VERIFICATION
// ============================================================================
const verifyAuth = (event) => {
  try {
    const authHeader = event.headers.authorization || event.headers.Authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({
          success: false,
          message: 'Token expired. Redirecting to login...',
          redirect: 'https://vtufest2026.acharyahabba.com/',
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
          message: 'Token expired. Redirecting to login...',
          redirect: 'https://vtufest2026.acharyahabba.com/',
        }),
      };
    }

    if (decoded.role !== 'PRINCIPAL' && decoded.role !== 'MANAGER') {
      throw new Error('Unauthorized: Principal or Manager role required');
    }

    return {
      user_id: decoded.user_id,
      college_id: decoded.college_id,
      role: decoded.role,
    };
  } catch (error) {
    throw error;
  }
};

// ============================================================================
// CHECK IF COLLEGE IS LOCKED
// ============================================================================
const checkLockStatus = async (pool, college_id) => {
  const result = await pool
    .request()
    .input('college_id', sql.Int, college_id)
    .query(`
      SELECT is_final_approved
      FROM colleges
      WHERE college_id = @college_id
    `);

  if (result.recordset.length === 0) {
    throw new Error('College not found');
  }

  return result.recordset[0].is_final_approved === 1;
};

// ============================================================================
// ACTION: FETCH
// ============================================================================
const fetchEventAssignments = async (pool, auth, body) => {
  const { event_slug } = body;

  if (!event_slug || !EVENT_TABLES[event_slug]) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid or missing event_slug' }),
    };
  }

  const tableName = EVENT_TABLES[event_slug];

  // Fetch participants
  const participantsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        et.person_id,
        et.person_type,
        et.full_name,
        et.phone,
        et.email,
        et.event_type
      FROM ${tableName} et
      WHERE et.college_id = @college_id
        AND et.event_type = 'participating'
      ORDER BY et.full_name
    `);

  // Fetch accompanists
  const accompanistsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        et.person_id,
        et.person_type,
        et.full_name,
        et.phone,
        et.email,
        et.event_type
      FROM ${tableName} et
      WHERE et.college_id = @college_id
        AND et.event_type = 'accompanying'
      ORDER BY et.full_name
    `);

  // Fetch approved students (not yet assigned to this event)
  const availableStudentsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        sa.student_id,
        s.full_name,
        s.usn,
        s.email,
        s.phone
      FROM student_applications sa
      INNER JOIN students s ON sa.student_id = s.student_id
      WHERE s.college_id = @college_id
        AND sa.status = 'APPROVED'
        AND sa.student_id NOT IN (
          SELECT person_id 
          FROM ${tableName} 
          WHERE college_id = @college_id 
            AND person_type = 'student'
        )
      ORDER BY s.full_name
    `);

  // Fetch accompanists (not yet assigned to this event)
  const availableAccompanistsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        accompanist_id,
        full_name,
        phone,
        email,
        accompanist_type
      FROM accompanists
      WHERE college_id = @college_id
        AND accompanist_id NOT IN (
          SELECT person_id 
          FROM ${tableName} 
          WHERE college_id = @college_id 
            AND person_type = 'accompanist'
        )
      ORDER BY full_name
    `);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      event_slug,
      participants: participantsResult.recordset.map(p => ({
        person_id: p.person_id,
        person_type: p.person_type,
        full_name: p.full_name,
        phone: p.phone,
        email: p.email,
      })),
      accompanists: accompanistsResult.recordset.map(a => ({
        person_id: a.person_id,
        person_type: a.person_type,
        full_name: a.full_name,
        phone: a.phone,
        email: a.email,
      })),
      available_students: availableStudentsResult.recordset.map(s => ({
        student_id: s.student_id,
        full_name: s.full_name,
        usn: s.usn,
        email: s.email,
        phone: s.phone,
      })),
      available_accompanists: availableAccompanistsResult.recordset.map(a => ({
        accompanist_id: a.accompanist_id,
        full_name: a.full_name,
        phone: a.phone,
        email: a.email,
        accompanist_type: a.accompanist_type,
      })),
    }),
  };
};

// ============================================================================
// ACTION: ADD
// ============================================================================
const addEventAssignment = async (pool, auth, body) => {
  const { event_slug, person_id, person_type, event_type } = body;

  if (!event_slug || !EVENT_TABLES[event_slug]) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid or missing event_slug' }),
    };
  }

  if (!person_id || !person_type || !event_type) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'person_id, person_type, and event_type are required' }),
    };
  }

  if (!['student', 'accompanist'].includes(person_type)) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'person_type must be "student" or "accompanist"' }),
    };
  }

  if (!['participating', 'accompanying'].includes(event_type)) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'event_type must be "participating" or "accompanying"' }),
    };
  }

  // Validate person_type and event_type combinations
  if (person_type === 'accompanist' && event_type === 'participating') {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Accompanists cannot be participants' }),
    };
  }

  // Check if college is locked
  const isLocked = await checkLockStatus(pool, auth.college_id);
  if (isLocked) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'College has final approval. Cannot modify assignments.' }),
    };
  }

  const tableName = EVENT_TABLES[event_slug];
  const transaction = pool.transaction();
  await transaction.begin();

  try {
    // Check if person exists and is approved (for students)
    if (person_type === 'student') {
      const studentCheck = await transaction
        .request()
        .input('student_id', sql.Int, person_id)
        .input('college_id', sql.Int, auth.college_id)
        .query(`
          SELECT sa.status
          FROM student_applications sa
          INNER JOIN students s ON sa.student_id = s.student_id
          WHERE sa.student_id = @student_id
            AND s.college_id = @college_id
        `);

      if (studentCheck.recordset.length === 0) {
        await transaction.rollback();
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'Student not found or does not belong to your college' }),
        };
      }

      if (studentCheck.recordset[0].status !== 'APPROVED') {
        await transaction.rollback();
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Only approved students can be assigned to events' }),
        };
      }
    } else {
      // Check if accompanist exists
      const accompCheck = await transaction
        .request()
        .input('accompanist_id', sql.Int, person_id)
        .input('college_id', sql.Int, auth.college_id)
        .query(`
          SELECT accompanist_id
          FROM accompanists
          WHERE accompanist_id = @accompanist_id
            AND college_id = @college_id
        `);

      if (accompCheck.recordset.length === 0) {
        await transaction.rollback();
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'Accompanist not found or does not belong to your college' }),
        };
      }
    }

    // Check for duplicate assignment
    const duplicateCheck = await transaction
      .request()
      .input('person_id', sql.Int, person_id)
      .input('person_type', sql.VarChar(15), person_type)
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        SELECT COUNT(*) AS count
        FROM ${tableName}
        WHERE person_id = @person_id
          AND person_type = @person_type
          AND college_id = @college_id
      `);

    if (duplicateCheck.recordset[0].count > 0) {
      await transaction.rollback();
      return {
        statusCode: 409,
        headers,
        body: JSON.stringify({ error: 'Person is already assigned to this event' }),
      };
    }

    // Get person details
    let personDetails;
    if (person_type === 'student') {
      const studentDetails = await transaction
        .request()
        .input('student_id', sql.Int, person_id)
        .query(`
          SELECT full_name, phone, email, passport_photo_url
          FROM students
          WHERE student_id = @student_id
        `);
      personDetails = studentDetails.recordset[0];
    } else {
      const accompDetails = await transaction
        .request()
        .input('accompanist_id', sql.Int, person_id)
        .query(`
          SELECT full_name, phone, email, passport_photo_url, accompanist_type
          FROM accompanists
          WHERE accompanist_id = @accompanist_id
        `);
      personDetails = accompDetails.recordset[0];
    }

    // Insert into event table
    await transaction
      .request()
      .input('person_id', sql.Int, person_id)
      .input('person_type', sql.VarChar(15), person_type)
      .input('full_name', sql.VarChar(255), personDetails.full_name)
      .input('phone', sql.VarChar(20), personDetails.phone)
      .input('email', sql.VarChar(255), personDetails.email)
      .input('photo_url', sql.VarChar(500), personDetails.passport_photo_url)
      .input('accompanist_type', sql.VarChar(20), personDetails.accompanist_type || null)
      .input('college_id', sql.Int, auth.college_id)
      .input('event_type', sql.VarChar(20), event_type)
      .input('assigned_by_user_id', sql.Int, auth.user_id)
      .query(`
        INSERT INTO ${tableName} (
          person_id, person_type, full_name, phone, email, photo_url,
          accompanist_type, college_id, event_type, assigned_by_user_id
        )
        VALUES (
          @person_id, @person_type, @full_name, @phone, @email, @photo_url,
          @accompanist_type, @college_id, @event_type, @assigned_by_user_id
        )
      `);

    await transaction.commit();

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: `${person_type === 'student' ? 'Student' : 'Accompanist'} assigned as ${event_type} successfully`,
      }),
    };
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
};

// ============================================================================
// ACTION: REMOVE
// ============================================================================
const removeEventAssignment = async (pool, auth, body) => {
  const { event_slug, person_id, person_type } = body;

  if (!event_slug || !EVENT_TABLES[event_slug]) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid or missing event_slug' }),
    };
  }

  if (!person_id || !person_type) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'person_id and person_type are required' }),
    };
  }

  // Check if college is locked
  const isLocked = await checkLockStatus(pool, auth.college_id);
  if (isLocked) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'College has final approval. Cannot modify assignments.' }),
    };
  }

  const tableName = EVENT_TABLES[event_slug];

  // Delete from event table
  const result = await pool
    .request()
    .input('person_id', sql.Int, person_id)
    .input('person_type', sql.VarChar(15), person_type)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      DELETE FROM ${tableName}
      WHERE person_id = @person_id
        AND person_type = @person_type
        AND college_id = @college_id
    `);

  if (result.rowsAffected[0] === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ error: 'Assignment not found' }),
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Assignment removed successfully',
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
    
    // If auth returned an error response, return it
    if (auth.statusCode) {
      return auth;
    }

    // PRINCIPAL can only FETCH
    if (auth.role === 'PRINCIPAL' && action !== 'FETCH') {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Principals can only fetch event assignments (read-only)' }),
      };
    }

    pool = await sql.connect(dbConfig);

    if (action === 'FETCH') {
      return await fetchEventAssignments(pool, auth, body);
    } else if (action === 'ADD') {
      return await addEventAssignment(pool, auth, body);
    } else if (action === 'REMOVE') {
      return await removeEventAssignment(pool, auth, body);
    } else {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid action. Supported: FETCH, ADD, REMOVE' }),
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