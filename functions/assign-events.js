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
  'classical_instrumental_percussion': 'event_classical_instr_percussion',
  'classical_instrumental_non_percussion': 'event_classical_instr_non_percussion',
  'light_vocal_solo': 'event_light_vocal_solo',
  'western_vocal_solo': 'event_western_vocal_solo',
  'group_song_indian': 'event_group_song_indian',
  'group_song_western': 'event_group_song_western',
  'folk_orchestra': 'event_folk_orchestra',
  'folk_tribal_dance': 'event_folk_dance',
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

  // Fetch participants (students in participant role)
  const participantsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        CASE 
          WHEN et.person_type = 'student' THEN et.student_id
          ELSE et.accompanist_id
        END AS person_id,
        et.person_type,
        et.full_name,
        CASE 
          WHEN et.person_type = 'student' THEN s.phone
          ELSE a.phone
        END AS phone,
        CASE 
          WHEN et.person_type = 'student' THEN s.email
          ELSE a.email
        END AS email
      FROM ${tableName} et
      LEFT JOIN students s ON et.person_type = 'student' AND et.student_id = s.student_id
      LEFT JOIN accompanists a ON et.person_type = 'accompanist' AND et.accompanist_id = a.accompanist_id
      WHERE et.college_id = @college_id
        AND et.role = 'participant'
      ORDER BY et.full_name
    `);

  // Fetch accompanists (anyone in accompanist role)
  const accompanistsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        CASE 
          WHEN et.person_type = 'student' THEN et.student_id
          ELSE et.accompanist_id
        END AS person_id,
        et.person_type,
        et.full_name,
        CASE 
          WHEN et.person_type = 'student' THEN s.phone
          ELSE a.phone
        END AS phone,
        CASE 
          WHEN et.person_type = 'student' THEN s.email
          ELSE a.email
        END AS email
      FROM ${tableName} et
      LEFT JOIN students s ON et.person_type = 'student' AND et.student_id = s.student_id
      LEFT JOIN accompanists a ON et.person_type = 'accompanist' AND et.accompanist_id = a.accompanist_id
      WHERE et.college_id = @college_id
        AND et.role = 'accompanist'
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
          SELECT student_id 
          FROM ${tableName} 
          WHERE college_id = @college_id 
            AND person_type = 'student'
            AND student_id IS NOT NULL
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
          SELECT accompanist_id 
          FROM ${tableName} 
          WHERE college_id = @college_id 
            AND person_type = 'accompanist'
            AND accompanist_id IS NOT NULL
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
    // Get college name
    const collegeResult = await transaction
      .request()
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        SELECT college_name
        FROM colleges
        WHERE college_id = @college_id
      `);

    const collegeName = collegeResult.recordset[0].college_name;

    // Check if person exists and is approved (for students)
    let personDetails;
    if (person_type === 'student') {
      const studentCheck = await transaction
        .request()
        .input('student_id', sql.Int, person_id)
        .input('college_id', sql.Int, auth.college_id)
        .query(`
          SELECT sa.status, s.full_name, s.usn
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

      personDetails = studentCheck.recordset[0];
    } else {
      // Check if accompanist exists
      const accompCheck = await transaction
        .request()
        .input('accompanist_id', sql.Int, person_id)
        .input('college_id', sql.Int, auth.college_id)
        .query(`
          SELECT full_name
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

      personDetails = accompCheck.recordset[0];
    }

    // Check for duplicate assignment
    const idColumn = person_type === 'student' ? 'student_id' : 'accompanist_id';
    const duplicateCheck = await transaction
      .request()
      .input('person_id', sql.Int, person_id)
      .input('person_type', sql.VarChar(15), person_type)
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        SELECT COUNT(*) AS count
        FROM ${tableName}
        WHERE ${idColumn} = @person_id
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

    // Convert event_type to role
    const role = event_type === 'participating' ? 'participant' : 'accompanist';

    // Insert into event table
    const insertQuery = person_type === 'student'
      ? `INSERT INTO ${tableName} (
          college_id, college_name, person_type, student_id, 
          full_name, usn, role
        ) VALUES (
          @college_id, @college_name, @person_type, @person_id,
          @full_name, @usn, @role
        )`
      : `INSERT INTO ${tableName} (
          college_id, college_name, person_type, accompanist_id,
          full_name, usn, role
        ) VALUES (
          @college_id, @college_name, @person_type, @person_id,
          @full_name, NULL, @role
        )`;

    await transaction
      .request()
      .input('college_id', sql.Int, auth.college_id)
      .input('college_name', sql.VarChar(255), collegeName)
      .input('person_type', sql.VarChar(20), person_type)
      .input('person_id', sql.Int, person_id)
      .input('full_name', sql.VarChar(255), personDetails.full_name)
      .input('usn', sql.VarChar(50), personDetails.usn || null)
      .input('role', sql.VarChar(20), role)
      .query(insertQuery);

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
  const idColumn = person_type === 'student' ? 'student_id' : 'accompanist_id';

  // Delete from event table
  const result = await pool
    .request()
    .input('person_id', sql.Int, person_id)
    .input('person_type', sql.VarChar(15), person_type)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      DELETE FROM ${tableName}
      WHERE ${idColumn} = @person_id
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