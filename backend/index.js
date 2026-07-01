// ============================================================
// Job Application Tracker API — v3 (PostgreSQL + bcrypt + JWT)
// Stack: Node.js + Express + pg + bcrypt + jsonwebtoken
// ============================================================

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const SALT_ROUNDS = 10;

app.use(express.json());

// ============================================================
// Database pool — with timeouts to avoid hanging connections
// ============================================================

const pool = new Pool({
  host:                   process.env.DB_HOST,
  user:                   process.env.DB_USER,
  password:               process.env.DB_PASSWORD,
  database:               process.env.DB_NAME,
  port:                   5432,
  max:                    10,
  idleTimeoutMillis:      30000,
  connectionTimeoutMillis: 5000,
});

// Catch errors on idle pool clients — prevents uncaught exception crashes
pool.on("error", (err) => {
  console.error("Unexpected pool error:", err.message);
});

// ============================================================
// Bootstrap: create tables, with retry on transient errors
// ============================================================

async function initDB(retries = 10, delay = 2000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id       SERIAL PRIMARY KEY,
          email    TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL
        );
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS jobs (
          id         SERIAL PRIMARY KEY,
          user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
          company    TEXT NOT NULL,
          job_title  TEXT NOT NULL,
          status     TEXT NOT NULL DEFAULT 'applied',
          notes      TEXT DEFAULT '',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      console.log("✅ Tables ready");
      return;
    } catch (err) {
      console.error(`❌ DB init attempt ${attempt}/${retries} failed: ${err.message}`);
      if (attempt === retries) throw err;
      await new Promise((res) => setTimeout(res, delay));
    }
  }
}

// ============================================================
// Middleware — verify JWT token on protected routes
// ============================================================

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }

  const token = authHeader.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, email }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ============================================================
// Helper — wraps async route handlers
// ============================================================

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ============================================================
// Health check — pings the DB so Docker knows if it's really up
// ============================================================

app.get(
  "/health",
  asyncHandler(async (_req, res) => {
    await pool.query("SELECT 1");
    res.json({ status: "OK" });
  })
);

// ============================================================
// Auth routes (public)
// ============================================================

// POST /register — Body: { email, password }
app.post(
  "/register",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashedPassword]
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });
  })
);

// POST /login — Body: { email, password } → returns JWT valid 24h
app.post(
  "/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const result = await pool.query(
      "SELECT id, email, password FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];
    const isValid = user && (await bcrypt.compare(password, user.password));

    if (!isValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.json({
      message: "Login successful",
      token,
      user: { id: user.id, email: user.email },
    });
  })
);

// ============================================================
// Job routes (protected)
// ============================================================

// POST /jobs — Body: { company, job_title, status?, notes? }
app.post(
  "/jobs",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const { company, job_title, status = "applied", notes = "" } = req.body;

    if (!company || !job_title) {
      return res.status(400).json({ error: "company and job_title are required" });
    }

    const result = await pool.query(
      `INSERT INTO jobs (user_id, company, job_title, status, notes)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [req.user.id, company, job_title, status, notes]
    );

    return res.status(201).json({ message: "Job added", job: result.rows[0] });
  })
);

// GET /jobs — jobs of the logged-in user, newest first
app.get(
  "/jobs",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const result = await pool.query(
      "SELECT * FROM jobs WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );

    return res.json({ count: result.rowCount, jobs: result.rows });
  })
);

// PUT /jobs/:id — Body (any subset): { status?, notes?, company?, job_title? }
app.put(
  "/jobs/:id",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const jobId = Number(req.params.id);

    const existing = await pool.query(
      "SELECT * FROM jobs WHERE id = $1 AND user_id = $2",
      [jobId, req.user.id]
    );

    if (existing.rowCount === 0) {
      return res.status(404).json({ error: "Job not found" });
    }

    const cur = existing.rows[0];

    const result = await pool.query(
      `UPDATE jobs
       SET company = $1, job_title = $2, status = $3, notes = $4
       WHERE id = $5
       RETURNING *`,
      [
        req.body.company   ?? cur.company,
        req.body.job_title ?? cur.job_title,
        req.body.status    ?? cur.status,
        req.body.notes     ?? cur.notes,
        jobId,
      ]
    );

    return res.json({ message: "Job updated", job: result.rows[0] });
  })
);

// DELETE /jobs/:id
app.delete(
  "/jobs/:id",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const jobId = Number(req.params.id);

    const result = await pool.query(
      "DELETE FROM jobs WHERE id = $1 AND user_id = $2 RETURNING *",
      [jobId, req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Job not found" });
    }

    return res.json({ message: "Job deleted", job: result.rows[0] });
  })
);

// ============================================================
// Global error handler
// ============================================================

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.code === "23505") {
    return res.status(409).json({ error: "Email already in use" });
  }

  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ============================================================
// Graceful shutdown — lets in-flight requests finish before exit
// ============================================================

let server;

function shutdown(signal) {
  console.log(`${signal} received — shutting down gracefully`);
  server.close(async () => {
    await pool.end();
    console.log("Pool closed. Bye.");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

// ============================================================
// Start
// ============================================================

initDB()
  .then(() => {
    server = app.listen(PORT, () => {
      console.log(`✅ Connected to PostgreSQL`);
      console.log(`🚀 Job Tracker API running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Failed to initialize DB after all retries:", err.message);
    process.exit(1);
  });
