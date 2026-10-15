const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
  console.error('Set SESSION_SECRET to a random value of at least 32 characters before production use.');
  process.exit(1);
}

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'users.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'victor.sid',
  secret: sessionSecret || crypto.randomBytes(48).toString('hex'),
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a little before trying again.' }
});

const emailIsValid = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const clean = (value) => typeof value === 'string' ? value.trim() : '';

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please log in to continue.' });
  next();
}

app.post('/api/register', authLimiter, async (req, res) => {
  const name = clean(req.body.name);
  const email = clean(req.body.email).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';

  if (name.length < 2 || name.length > 80) {
    return res.status(400).json({ error: 'Name must be between 2 and 80 characters.' });
  }
  if (!emailIsValid(email) || email.length > 254) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
      .run(name, email, passwordHash);
    req.session.regenerate((sessionError) => {
      if (sessionError) return res.status(500).json({ error: 'Could not start your session.' });
      req.session.user = { id: result.lastInsertRowid, name, email };
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ error: 'Account created, but sign-in failed. Please log in.' });
        res.status(201).json({ message: 'Account created successfully. You are now signed in.' });
      });
    });
  } catch (error) {
    if (error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Unable to create your account right now.' });
  }
});

app.post('/api/login', authLimiter, (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!emailIsValid(email) || !password) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }
  const user = db.prepare('SELECT id, name, email, password_hash FROM users WHERE email = ?').get(email);
  // Same public error for unknown email and incorrect password.
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }
  req.session.regenerate((error) => {
    if (error) return res.status(500).json({ error: 'Could not start your session.' });
    req.session.user = { id: user.id, name: user.name, email: user.email };
    req.session.save((saveError) => {
      if (saveError) return res.status(500).json({ error: 'Could not save your session. Please try again.' });
      res.json({ message: 'Login successful.' });
    });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ error: 'Could not log you out. Please try again.' });
    res.clearCookie('victor.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.json({ message: 'Logged out successfully.' });
  });
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// Example protected endpoint: use the same requireAuth middleware for private API routes.
app.get('/api/private-example', requireAuth, (req, res) => {
  res.json({ message: `Welcome, ${req.session.user.name}. This endpoint requires login.` });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`Victor Coker portfolio running at http://localhost:${PORT}`);
});
