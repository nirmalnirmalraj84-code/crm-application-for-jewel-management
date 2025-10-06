require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const compression = require('compression');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const { getDb, initDb } = require('./db/db');

// Ensure required directories exist
fs.mkdirSync(path.join(__dirname, 'db'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

const app = express();

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet());
app.use(compression());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('dev'));

const sessionSecret = process.env.SESSION_SECRET || 'dev-secret-change-me';
app.use(
  session({
    store: new MemoryStore({ checkPeriod: 1000 * 60 * 60 }), // prune expired entries hourly
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 8 }, // 8 hours
  })
);

// Simple flash messages using session
app.use((req, res, next) => {
  res.locals.messages = req.session.messages || [];
  res.locals.currentUser = req.session.user || null;
  req.session.messages = [];
  next();
});

function addMessage(req, type, text) {
  if (!req.session.messages) req.session.messages = [];
  req.session.messages.push({ type, text });
}

// Auth guards
function requireStudent(req, res, next) {
  if (req.session.user && req.session.user.role === 'student') return next();
  addMessage(req, 'error', 'Please sign in as a student.');
  return res.redirect('/student/login');
}

function requireAdmin(req, res, next) {
  if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'principal')) {
    return next();
  }
  addMessage(req, 'error', 'Please sign in as admin or principal.');
  return res.redirect('/admin/login');
}

// Initialize DB (creates tables if missing) handled below before starting server

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

// Student auth
app.get('/student/login', (req, res) => {
  res.render('student/login');
});

app.post('/student/login', (req, res) => {
  const { email, password } = req.body;
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND role = "student"').get(email);
  if (!user) {
    addMessage(req, 'error', 'Invalid credentials.');
    return res.redirect('/student/login');
  }
  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) {
    addMessage(req, 'error', 'Invalid credentials.');
    return res.redirect('/student/login');
  }
  req.session.user = { id: user.id, name: user.name, role: user.role, email: user.email };
  return res.redirect('/student/staff');
});

app.get('/student/forgot', (req, res) => {
  res.render('student/forgot');
});

app.post('/student/forgot', (req, res) => {
  const { email } = req.body;
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND role = "student"').get(email);
  if (!user) {
    addMessage(req, 'info', 'If that account exists, a reset link was generated.');
    return res.redirect('/student/forgot');
  }
  const { v4: uuidv4 } = require('uuid');
  const token = uuidv4();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 30).toISOString(); // 30 minutes
  db.prepare('UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?').run(token, expiresAt, user.id);
  // In a real app, email this link. Here we display it as a one-time message.
  addMessage(req, 'info', `Password reset link: /student/reset/${token}`);
  return res.redirect('/student/forgot');
});

app.get('/student/reset/:token', (req, res) => {
  const { token } = req.params;
  const db = getDb();
  const user = db
    .prepare('SELECT * FROM users WHERE reset_token = ? AND role = "student"')
    .get(token);
  if (!user) {
    addMessage(req, 'error', 'Invalid or expired reset token.');
    return res.redirect('/student/forgot');
  }
  const expired = user.reset_token_expires_at && new Date(user.reset_token_expires_at).getTime() < Date.now();
  if (expired) {
    addMessage(req, 'error', 'Reset token has expired.');
    return res.redirect('/student/forgot');
  }
  res.render('student/reset', { token });
});

app.post('/student/reset/:token', (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  const db = getDb();
  const user = db
    .prepare('SELECT * FROM users WHERE reset_token = ? AND role = "student"')
    .get(token);
  if (!user) {
    addMessage(req, 'error', 'Invalid or expired reset token.');
    return res.redirect('/student/forgot');
  }
  const expired = user.reset_token_expires_at && new Date(user.reset_token_expires_at).getTime() < Date.now();
  if (expired) {
    addMessage(req, 'error', 'Reset token has expired.');
    return res.redirect('/student/forgot');
  }
  const passwordHash = bcrypt.hashSync(password, 10);
  db.prepare(
    'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?'
  ).run(passwordHash, user.id);
  addMessage(req, 'success', 'Password updated. Please sign in.');
  return res.redirect('/student/login');
});

// Student flows
app.get('/student/staff', requireStudent, (req, res) => {
  const db = getDb();
  const staff = db.prepare('SELECT id, name, subject FROM staff ORDER BY name').all();
  res.render('student/staff_list', { staff });
});

app.get('/student/feedback/:staffId', requireStudent, (req, res) => {
  const db = getDb();
  const staff = db.prepare('SELECT id, name, subject FROM staff WHERE id = ?').get(req.params.staffId);
  if (!staff) {
    addMessage(req, 'error', 'Staff not found.');
    return res.redirect('/student/staff');
  }
  // Check if already submitted feedback
  const existing = db
    .prepare('SELECT id FROM feedback WHERE student_id = ? AND staff_id = ?')
    .get(req.session.user.id, staff.id);
  res.render('student/feedback', { staff, alreadySubmitted: !!existing });
});

app.post('/student/feedback/:staffId', requireStudent, (req, res) => {
  const db = getDb();
  const staff = db.prepare('SELECT id FROM staff WHERE id = ?').get(req.params.staffId);
  if (!staff) {
    addMessage(req, 'error', 'Staff not found.');
    return res.redirect('/student/staff');
  }
  const { rating, comments } = req.body;
  const normalized = ['Average', 'Good', 'Excellent'].includes(rating) ? rating : 'Average';
  try {
    db.prepare(
      'INSERT INTO feedback (student_id, staff_id, rating, comments, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(req.session.user.id, staff.id, normalized, (comments || '').trim(), new Date().toISOString());
    addMessage(req, 'success', 'Thank you! Your feedback has been recorded.');
  } catch (e) {
    // Enforce one feedback per staff per student
    addMessage(req, 'info', 'You have already submitted feedback for this staff.');
  }
  return res.redirect('/student/staff');
});

// Admin/Principal auth
app.get('/admin/login', (req, res) => {
  res.render('admin/login');
});

app.post('/admin/login', (req, res) => {
  const { email, password } = req.body;
  const db = getDb();
  const user = db
    .prepare('SELECT * FROM users WHERE email = ? AND (role = "admin" OR role = "principal")')
    .get(email);
  if (!user) {
    addMessage(req, 'error', 'Invalid credentials.');
    return res.redirect('/admin/login');
  }
  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) {
    addMessage(req, 'error', 'Invalid credentials.');
    return res.redirect('/admin/login');
  }
  req.session.user = { id: user.id, name: user.name, role: user.role, email: user.email };
  return res.redirect('/admin');
});

app.get('/admin', requireAdmin, (req, res) => {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT s.id AS staff_id, s.name AS staff_name, s.subject,
              COUNT(f.id) AS total,
              SUM(CASE WHEN f.rating = 'Average' THEN 1 ELSE 0 END) AS avg_count,
              SUM(CASE WHEN f.rating = 'Good' THEN 1 ELSE 0 END) AS good_count,
              SUM(CASE WHEN f.rating = 'Excellent' THEN 1 ELSE 0 END) AS excellent_count,
              ROUND(AVG(CASE 
                WHEN f.rating = 'Average' THEN 1 
                WHEN f.rating = 'Good' THEN 2 
                WHEN f.rating = 'Excellent' THEN 3 
              END), 2) AS avg_score
       FROM staff s
       LEFT JOIN feedback f ON f.staff_id = s.id
       GROUP BY s.id
       ORDER BY s.name`
    )
    .all();
  res.render('admin/dashboard', { summaries: rows });
});

app.get('/admin/staff/:id', requireAdmin, (req, res) => {
  const db = getDb();
  const staff = db.prepare('SELECT id, name, subject FROM staff WHERE id = ?').get(req.params.id);
  if (!staff) {
    addMessage(req, 'error', 'Staff not found.');
    return res.redirect('/admin');
  }
  const counts = db
    .prepare(
      `SELECT 
         SUM(CASE WHEN rating = 'Average' THEN 1 ELSE 0 END) AS avg_count,
         SUM(CASE WHEN rating = 'Good' THEN 1 ELSE 0 END) AS good_count,
         SUM(CASE WHEN rating = 'Excellent' THEN 1 ELSE 0 END) AS excellent_count,
         COUNT(*) AS total,
         ROUND(AVG(CASE 
           WHEN rating = 'Average' THEN 1 
           WHEN rating = 'Good' THEN 2 
           WHEN rating = 'Excellent' THEN 3 
         END), 2) AS avg_score
       FROM feedback WHERE staff_id = ?`
    )
    .get(staff.id);
  const comments = db
    .prepare(
      `SELECT f.comments, f.created_at, u.name AS student_name 
       FROM feedback f 
       JOIN users u ON u.id = f.student_id
       WHERE f.staff_id = ? AND TRIM(f.comments) != ''
       ORDER BY f.created_at DESC`
    )
    .all(staff.id);
  res.render('admin/staff_detail', { staff, counts, comments });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// 404
app.use((req, res) => {
  res.status(404).render('404');
});

const port = process.env.PORT || 3000;
(async () => {
  try {
    await initDb();
    if (process.env.NODE_ENV !== 'test') {
      app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
      });
    }
  } catch (err) {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  }
})();

module.exports = app;
