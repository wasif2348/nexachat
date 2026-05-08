/**
 * NexaChat — Database Layer (sql.js — pure JS SQLite)
 * No native compilation required.
 * Persists to nexachat.db on disk after every write batch.
 */

const initSqlJs = require('sql.js');
const path      = require('path');
const fs        = require('fs');

const DB_PATH = path.join(__dirname, 'nexachat.db');

let db; // sql.js Database instance

// ─── Persist to disk ──────────────────────────────────────────────────────────
function saveDB() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) {
    console.error('[DB] Save error:', e.message);
  }
}

// ─── Convert sql.js exec result rows to array of objects ──────────────────────
function rowsToObjects(results) {
  if (!results || results.length === 0) return [];
  const { columns, values } = results[0];
  return values.map(row => {
    const obj = {};
    columns.forEach((col, i) => { obj[col] = row[i]; });
    return obj;
  });
}

// ─── Wrapper helpers to mimic better-sqlite3 API ─────────────────────────────
// prepare(query).get()   → first row as object (or undefined)
// prepare(query).all()   → all rows as array of objects
// prepare(query).run()   → {lastInsertRowid, changes}
function prepare(query) {
  return {
    get: (...params) => {
      const stmt = db.prepare(query);
      stmt.bind(params);
      const row = stmt.step() ? stmt.getAsObject() : undefined;
      stmt.free();
      return row;
    },
    all: (...params) => {
      const stmt = db.prepare(query);
      stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      stmt.free();
      return rows;
    },
    run: (...params) => {
      const stmt = db.prepare(query);
      stmt.bind(params);
      stmt.step();
      stmt.free();
      const lastId = rowsToObjects(db.exec('SELECT last_insert_rowid() as id'))[0]?.id;
      saveDB();
      return { lastInsertRowid: lastId, changes: db.getRowsModified() };
    }
  };
}

// ─── Raw vulnerable exec (for SQLi demo) ──────────────────────────────────────
// Returns first row as object, or undefined. Throws on SQL error.
function execVulnerable(rawSQL) {
  const results = db.exec(rawSQL);
  return rowsToObjects(results)[0];
}

// ─── Init ─────────────────────────────────────────────────────────────────────
async function initDB() {
  const SQL = await initSqlJs();

  // Load existing DB from disk, or create new
  if (fs.existsSync(DB_PATH)) {
    const fileData = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileData);
    console.log('[DB] Loaded existing database from disk');
  } else {
    db = new SQL.Database();
    console.log('[DB] Created new in-memory database');
  }

  // ─── Schema ──────────────────────────────────────────────────────────────────
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      username     TEXT    UNIQUE NOT NULL,
      password     TEXT    NOT NULL,
      role         TEXT    DEFAULT 'user',
      avatar_color TEXT    DEFAULT '#3b82f6',
      bio          TEXT    DEFAULT '',
      created_at   TEXT    DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS rooms (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL UNIQUE,
      description TEXT,
      icon        TEXT DEFAULT '#'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id      INTEGER NOT NULL,
      user_id      INTEGER NOT NULL,
      username     TEXT    NOT NULL,
      avatar_color TEXT    DEFAULT '#3b82f6',
      text         TEXT    NOT NULL,
      created_at   TEXT    DEFAULT (datetime('now'))
    )
  `);

  // ─── Seed Users (INSERT OR IGNORE — safe to run every boot) ──────────────────
  const demoUsers = [
    { username: 'admin',    password: 'admin123', role: 'admin', color: '#ef4444', bio: 'Platform Administrator' },
    { username: 'alice',    password: 'alice123', role: 'user',  color: '#8b5cf6', bio: 'Frontend Engineer' },
    { username: 'bob',      password: 'bob123',   role: 'user',  color: '#10b981', bio: 'Backend Developer' },
    { username: 'attacker', password: 'hack3r',   role: 'user',  color: '#f59e0b', bio: 'Security Researcher' },
  ];
  for (const u of demoUsers) {
    db.run(
      `INSERT OR IGNORE INTO users (username, password, role, avatar_color, bio) VALUES (?, ?, ?, ?, ?)`,
      [u.username, u.password, u.role, u.color, u.bio]
    );
  }

  // ─── Seed Rooms ───────────────────────────────────────────────────────────────
  const demoRooms = [
    { name: 'general',       desc: 'General discussion for the whole team',              icon: '💬' },
    { name: 'announcements', desc: 'Important company announcements — admins only',      icon: '📢' },
    { name: 'tech-talk',     desc: 'Engineering, code reviews & technical deep-dives',   icon: '⚙️' },
    { name: 'random',        desc: 'Off-topic, memes & Friday vibes',                    icon: '🎲' },
  ];
  for (const r of demoRooms) {
    db.run(`INSERT OR IGNORE INTO rooms (name, description, icon) VALUES (?, ?, ?)`, [r.name, r.desc, r.icon]);
  }

  // ─── Seed Messages (only if empty) ────────────────────────────────────────────
  const [[msgCount]] = db.exec('SELECT COUNT(*) as n FROM messages')[0]?.values || [[0]];
  if (msgCount === 0) {
    const adminUser = prepare('SELECT * FROM users WHERE username = ?').get('admin');
    const alice     = prepare('SELECT * FROM users WHERE username = ?').get('alice');
    const bob       = prepare('SELECT * FROM users WHERE username = ?').get('bob');
    const genRoom   = prepare("SELECT * FROM rooms WHERE name = ?").get('general');
    const annRoom   = prepare("SELECT * FROM rooms WHERE name = ?").get('announcements');
    const techRoom  = prepare("SELECT * FROM rooms WHERE name = ?").get('tech-talk');

    const insMsg = (roomId, userId, username, color, text) =>
      db.run(`INSERT INTO messages (room_id, user_id, username, avatar_color, text) VALUES (?, ?, ?, ?, ?)`,
             [roomId, userId, username, color, text]);

    // General
    insMsg(genRoom.id, adminUser.id, 'admin', adminUser.avatar_color, '👋 Welcome to NexaChat! Your new enterprise messaging platform. Feel free to explore all the channels.');
    insMsg(genRoom.id, alice.id,     'alice', alice.avatar_color,     'Thanks @admin! The new interface looks amazing. Really clean UI.');
    insMsg(genRoom.id, bob.id,       'bob',   bob.avatar_color,       'Agreed. Loving the dark theme. Has anyone checked out #tech-talk yet?');
    insMsg(genRoom.id, alice.id,     'alice', alice.avatar_color,     "Yeah! There's already a thread about the new auth system. Go check it out.");
    insMsg(genRoom.id, adminUser.id, 'admin', adminUser.avatar_color, "Don't forget to check #announcements for the Q1 security report 🔒");

    // Announcements
    insMsg(annRoom.id, adminUser.id, 'admin', adminUser.avatar_color, '📢 NexaChat v2.0 is now LIVE! New features: rooms, user profiles, file sharing & real-time typing indicators. Report bugs to #general.');
    insMsg(annRoom.id, adminUser.id, 'admin', adminUser.avatar_color, '🔒 SECURITY NOTICE: All staff must update passwords before Friday. Contact IT if needed.');

    // Tech Talk
    insMsg(techRoom.id, bob.id,   'bob',   bob.avatar_color,   "Anyone else notice the login endpoint doesn't sanitize inputs? I was testing with Burp Suite...");
    insMsg(techRoom.id, alice.id, 'alice', alice.avatar_color, 'Yeah raised a ticket last week. Marked as low priority unfortunately 😬');
    insMsg(techRoom.id, bob.id,   'bob',   bob.avatar_color,   "Low priority?? A SQL injection in login is definitely P0. I'm escalating to @admin.");

    saveDB();
    console.log('[DB] Seeded demo messages');
  }

  saveDB();
  console.log('[DB] NexaChat database ready ✅');
}

function getDB()      { return db; }
function getPrepare() { return prepare; }

module.exports = { initDB, getDB, getPrepare, execVulnerable, saveDB };
