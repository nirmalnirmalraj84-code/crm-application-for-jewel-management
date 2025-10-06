const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');

let SQL; // sql.js module
let db; // sql.js Database instance
let initialized = false;

const dbPath = path.join(__dirname, 'database.sqlite');

async function initDb() {
  if (initialized) return;
  if (!SQL) {
    SQL = await initSqlJs({
      locateFile: (file) => require.resolve('sql.js/dist/' + file),
    });
  }
  if (fs.existsSync(dbPath)) {
    const fileBuffer = fs.readFileSync(dbPath);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK(role IN ('student','admin','principal')),
      password_hash TEXT NOT NULL,
      reset_token TEXT,
      reset_token_expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      subject TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      staff_id INTEGER NOT NULL,
      rating TEXT NOT NULL CHECK(rating IN ('Average','Good','Excellent')),
      comments TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(student_id, staff_id),
      FOREIGN KEY(student_id) REFERENCES users(id),
      FOREIGN KEY(staff_id) REFERENCES staff(id)
    );
  `);

  persist();
  initialized = true;
}

function persist() {
  const data = db.export();
  fs.writeFileSync(dbPath, Buffer.from(data));
}

function getDb() {
  if (!initialized) {
    throw new Error('Database not initialized. Call initDb() first.');
  }
  return {
    exec(sql) {
      db.exec(sql);
      persist();
    },
    prepare(sql) {
      return {
        get: (...params) => {
          const stmt = db.prepare(sql);
          try {
            stmt.bind(params);
            if (stmt.step()) {
              const row = stmt.getAsObject();
              return row;
            }
            return undefined;
          } finally {
            stmt.free();
          }
        },
        all: (...params) => {
          const stmt = db.prepare(sql);
          try {
            stmt.bind(params);
            const rows = [];
            while (stmt.step()) {
              rows.push(stmt.getAsObject());
            }
            return rows;
          } finally {
            stmt.free();
          }
        },
        run: (...params) => {
          const stmt = db.prepare(sql);
          try {
            stmt.bind(params);
            // For statements like INSERT/UPDATE, step until done
            while (stmt.step()) {}
          } finally {
            stmt.free();
          }
          // Emulate lastInsertRowid
          let lastId = 0;
          try {
            const check = db.prepare('SELECT last_insert_rowid() AS id');
            if (check.step()) {
              lastId = check.getAsObject().id;
            }
            check.free();
          } catch (_) {}
          persist();
          return { lastInsertRowid: lastId };
        },
      };
    },
  };
}

module.exports = { getDb, initDb };
