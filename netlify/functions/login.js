// netlify/functions/login.js
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');

// Rate limiting en mémoire (simple)
const loginAttempts = new Map();

// Protection XSS
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input
    .replace(/[<>\"\'&]/g, (char) => {
      const entities = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return entities[char];
    })
    .trim()
    .slice(0, 255); // Limiter la longueur
}

// Validation email
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
}

exports.handler = async (event) => {
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block'
  };

  // Handle OPTIONS request
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const body = JSON.parse(event.body);
    let { email, password } = body;

    // Sanitize inputs (protection XSS)
    email = sanitizeInput(email);
    password = sanitizeInput(password);

    // Validation
    if (!email || !password) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Email et mot de passe requis' })
      };
    }

    if (!isValidEmail(email)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Format email invalide' })
      };
    }

    if (password.length < 6 || password.length > 128) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Mot de passe invalide' })
      };
    }

    // Rate limiting check
    const now = Date.now();
    const attemptData = loginAttempts.get(email) || { count: 0, lockUntil: 0 };

    // Si verrouillé
    if (attemptData.lockUntil > now) {
      const remainingSeconds = Math.ceil((attemptData.lockUntil - now) / 1000);
      return {
        statusCode: 429,
        headers,
        body: JSON.stringify({ 
          error: 'Rate limited',
          remainingSeconds 
        })
      };
    }

    // Reset si le délai est passé
    if (attemptData.lockUntil > 0 && attemptData.lockUntil <= now) {
      attemptData.count = 0;
      attemptData.lockUntil = 0;
    }

    // Connexion à Turso
    const client = createClient({
      url: 'libsql://seek-beatifullemonwithstrawberry.aws-us-east-1.turso.io',
      authToken: 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NjY5NTMyOTgsImlkIjoiYTI0MWE5OWYtYWVlZS00OGEwLTk1Y2MtNDkxMmRhMTkxZWQ1IiwicmlkIjoiYTE0MjJkMjYtODg1Yi00MzU2LTg1YmEtZDAwMjI4N2RjYjg4In0.TsS4EqjlQBLFcvn3C_t-8GT1mpfiDpQCoYl3bqXSxnfnBdYNksO_zhwdrZzzzNFC1lZyVIfu5f8Vp6eA23ROCg'
    });

    // Chercher l'utilisateur (avec prepared statement pour éviter SQL injection)
    const result = await client.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [email]
    });

    if (result.rows.length === 0) {
      // Incrémenter les tentatives
      attemptData.count++;
      if (attemptData.count >= 3) {
        attemptData.lockUntil = now + 30000; // 30 secondes
      }
      loginAttempts.set(email, attemptData);

      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          error: 'Email ou mot de passe incorrect',
          attemptsLeft: Math.max(0, 3 - attemptData.count)
        })
      };
    }

    const user = result.rows[0];

    // Vérifier le mot de passe
    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      // Incrémenter les tentatives
      attemptData.count++;
      if (attemptData.count >= 3) {
        attemptData.lockUntil = now + 30000; // 30 secondes
      }
      loginAttempts.set(email, attemptData);

      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          error: 'Email ou mot de passe incorrect',
          attemptsLeft: Math.max(0, 3 - attemptData.count)
        })
      };
    }

    // Connexion réussie - reset les tentatives
    loginAttempts.delete(email);

    // Créer un token sécurisé
    const sessionToken = Buffer.from(
      JSON.stringify({
        id: user.id,
        email: user.email,
        timestamp: Date.now(),
        random: Math.random().toString(36)
      })
    ).toString('base64');

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        token: sessionToken,
        email: user.email
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Erreur serveur' })
    };
  }
};