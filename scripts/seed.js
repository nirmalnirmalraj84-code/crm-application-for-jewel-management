const bcrypt = require('bcryptjs');
const { getDb, initDb } = require('../db/db');

(async function main() {
  await initDb();
  const db = getDb();

  const studentPassword = bcrypt.hashSync('student123', 10);
  const adminPassword = bcrypt.hashSync('admin123', 10);
  const principalPassword = bcrypt.hashSync('principal123', 10);

  // Upsert helper
  function upsertUser(name, email, role, passwordHash) {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return existing.id;
    const info = db
      .prepare('INSERT INTO users (name, email, role, password_hash) VALUES (?, ?, ?, ?)')
      .run(name, email, role, passwordHash);
    return info.lastInsertRowid;
  }

  function upsertStaff(name, subject) {
    const existing = db.prepare('SELECT id FROM staff WHERE name = ? AND subject = ?').get(name, subject);
    if (existing) return existing.id;
    const info = db.prepare('INSERT INTO staff (name, subject) VALUES (?, ?)').run(name, subject);
    return info.lastInsertRowid;
  }

  const studentId = upsertUser('Student One', 'student1@college.edu', 'student', studentPassword);
  const adminId = upsertUser('Site Admin', 'admin@college.edu', 'admin', adminPassword);
  const principalId = upsertUser('Principal', 'principal@college.edu', 'principal', principalPassword);

  const staff1 = upsertStaff('Alice Johnson', 'Mathematics');
  const staff2 = upsertStaff('Bob Smith', 'Physics');
  const staff3 = upsertStaff('Carol Davis', 'Chemistry');

  // Seed a few feedback rows for demo (catch unique constraint if re-run)
  try {
    db.prepare('INSERT INTO feedback (student_id, staff_id, rating, comments) VALUES (?, ?, ?, ?)')
      .run(studentId, staff1, 'Excellent', 'Very clear explanations.');
  } catch (_) {}

  try {
    db.prepare('INSERT INTO feedback (student_id, staff_id, rating, comments) VALUES (?, ?, ?, ?)')
      .run(studentId, staff2, 'Good', 'Engaging labs, could slow down a bit.');
  } catch (_) {}

  console.log('Seed complete.');
})();
