// ============================================================
// Login & Registration with Session Variables
// Web Programming - Fall 2026
//
// Features:
//   /register  - creates a new user (password hashed with bcrypt)
//   /login     - checks credentials and stores the username in the session
//   /profile   - protected page that shows the logged-in username
//   /logout    - destroys the session and sends the user back to login
// ============================================================

// ---------- Required modules ----------
const express = require('express');          // web framework
const session = require('express-session');  // session variable support
const mysql = require('mysql2');             // MySQL driver
const bcrypt = require('bcryptjs');          // password hashing
const path = require('path');                // builds file paths safely

const app = express();
const PORT = 3000;

// ---------- Middleware ----------

// Parse form data sent with method="POST" so it shows up in req.body
app.use(express.urlencoded({ extended: true }));

// Serve register.html and login.html from the /public folder
app.use(express.static(path.join(__dirname, 'public')));

// Set up session storage.
// Each browser gets a cookie with a session ID; the data itself
// (e.g. req.session.username) is kept on the server.
app.use(session({
  secret: process.env.SESSION_SECRET || 'webprog-session-secret', // signs the session cookie
  resave: false,             // don't re-save the session if nothing changed
  saveUninitialized: false,  // don't create a session until something is stored
  cookie: { maxAge: 1000 * 60 * 30 } // session expires after 30 minutes
}));

// ---------- Database connection ----------
// The root password is read from an environment variable so it is
// never stored in the code or pushed to GitHub.
// Windows:  set ROOTPASS=yourpassword   then   node server.js
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.ROOTPASS,
  database: 'appdb'
});

db.connect(err => {
  if (err) {
    console.error('DB connection failed:', err.message);
    process.exit(1); // stop the app if the database is unreachable
  }
  console.log('Connected to MySQL database!');
});

// ---------- Routes ----------

// Home page: send logged-in users to their profile, everyone else to register
app.get('/', (req, res) => {
  if (req.session.username) return res.redirect('/profile');
  res.redirect('/register.html');
});

// REGISTER: save a new user to the users table
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Make sure every field was filled in
  if (!username || !email || !password) {
    return res.send('<p>All fields are required.</p><a href="/register.html">Back to register</a>');
  }

  try {
    // Hash the password so the plain text is never stored
    const hashed = await bcrypt.hash(password, 10);

    // Parameterized query (?) prevents SQL injection
    db.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [username, email, hashed],
      err => {
        if (err) {
          // The email column is UNIQUE, so a repeat email lands here
          if (err.code === 'ER_DUP_ENTRY') {
            return res.send('<p>That email is already registered.</p><a href="/register.html">Back to register</a>');
          }
          console.error(err);
          return res.send('<p>Registration failed.</p><a href="/register.html">Back to register</a>');
        }
        res.send('<h2>You have successfully registered!</h2><a href="/login.html">Go to login</a>');
      }
    );
  } catch (e) {
    console.error(e);
    res.send('<p>Server error.</p><a href="/register.html">Back to register</a>');
  }
});

// LOGIN: check the username/password and start a session
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const failMsg = '<h2>The login credentials were incorrect.</h2><a href="/login.html">Back to login</a>';

  // Look up the user by username
  db.query('SELECT * FROM users WHERE name = ?', [username], async (err, rows) => {
    if (err || rows.length === 0) return res.send(failMsg);

    // Compare the typed password with the stored hash
    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) return res.send(failMsg);

    // Success: store user data in session variables
    req.session.username = rows[0].name;
    req.session.email = rows[0].email;

    res.send(`
      <h2>You have logged in successfully!</h2>
      <p>Welcome, ${escapeHtml(req.session.username)}.</p>
      <a href="/profile">Go to your profile</a> |
      <a href="/logout">Log out</a>
    `);
  });
});

// PROFILE: only visible when logged in; reads the username from the session
app.get('/profile', (req, res) => {
  // No session variable means the user is not logged in
  if (!req.session.username) {
    return res.send('<h2>You must be logged in to view this page.</h2><a href="/login.html">Go to login</a>');
  }

  res.send(`
    <h1>Profile</h1>
    <p>Username: <strong>${escapeHtml(req.session.username)}</strong></p>
    <p>Email: ${escapeHtml(req.session.email)}</p>
    <a href="/logout">Log out</a>
  `);
});

// LOGOUT: destroy the session so the session variables are gone
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.send('<p>Could not log out.</p><a href="/profile">Back to profile</a>');
    }
    res.clearCookie('connect.sid'); // remove the session cookie from the browser
    res.send('<h2>You have been logged out.</h2><a href="/login.html">Back to login</a>');
  });
});

// ---------- Helper ----------
// Escapes special characters so user input can't inject HTML into a page
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// ---------- Start the server ----------
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));