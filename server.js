const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database file path
const DB_FILE = path.join(__dirname, 'data', 'users.json');

// Read users from file
function readUsers() {
  if (!fs.existsSync(DB_FILE)) return [];
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
}

// Save users to file
function saveUsers(users) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// Validate email
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// GET / - Check server
app.get('/', (req, res) => {
  res.json({ message: '⚡ Hustl API is running!' });
});

// POST /signup - Register new user WITH password
app.post('/signup', async (req, res) => {
  const name     = (req.body.name     || '').trim();
  const email    = (req.body.email    || '').trim();
  const role     = (req.body.role     || '').trim().toLowerCase();
  const password = (req.body.password || '').trim();

  // Validation
  const errors = {};
  if (!name || name.length < 2)   errors.name     = 'Name is required.';
  if (!email)                      errors.email    = 'Email is required.';
  else if (!isValidEmail(email))   errors.email    = 'Enter a valid email.';
  if (!password)                   errors.password = 'Password is required.';
  else if (password.length < 6)   errors.password = 'Password must be at least 6 characters.';
  if (!['student', 'business'].includes(role)) errors.role = 'Role must be student or business.';

  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ success: false, message: 'Signup failed.', errors });
  }

  // Check if email already exists
  const users = readUsers();
  const exists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (exists) {
    return res.status(409).json({
      success: false,
      message: 'Email already registered.',
      errors: { email: 'This email already exists.' }
    });
  }

  // Hash the password before saving
  const passwordHash = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(),
    name,
    email: email.toLowerCase(),
    role,
    passwordHash,
    dateJoined: new Date().toISOString()
  };

  users.push(newUser);
  saveUsers(users);

  return res.status(201).json({
    success: true,
    message: `Welcome to Hustl, ${newUser.name}!`,
    user: {
      id:         newUser.id,
      name:       newUser.name,
      email:      newUser.email,
      role:       newUser.role,
      dateJoined: newUser.dateJoined
    }
  });
});

// POST /login - Login with email + password
app.post('/login', async (req, res) => {
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password = (req.body.password || '').trim();

  // Validation
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required.'
    });
  }

  // Find user
  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'No account found with this email.',
      errors: { email: 'No account found with this email.' }
    });
  }

  // Check password
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.status(401).json({
      success: false,
      message: 'Incorrect password.',
      errors: { password: 'Incorrect password. Try again.' }
    });
  }

  // Success
  return res.json({
    success: true,
    message: `Welcome back, ${user.name}!`,
    user: {
      id:    user.id,
      name:  user.name,
      email: user.email,
      role:  user.role
    }
  });
});

// GET /users - Get all users
app.get('/users', (req, res) => {
  const users = readUsers();
  // Never send passwordHash to frontend
  const safe = users.map(({ passwordHash, ...rest }) => rest);
  return res.json({ success: true, total: safe.length, users: safe });
});

// GET /users/:id - Get one user
app.get('/users/:id', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === Number(req.params.id));
  if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
  const { passwordHash, ...safe } = user;
  return res.json({ success: true, user: safe });
});

// DELETE /users/:id - Delete a user
app.delete('/users/:id', (req, res) => {
  const users = readUsers();
  const index = users.findIndex(u => u.id === Number(req.params.id));
  if (index === -1) return res.status(404).json({ success: false, message: 'User not found.' });
  const removed = users.splice(index, 1)[0];
  saveUsers(users);
  return res.json({ success: true, message: `${removed.name} removed.` });
});

// Start server
app.listen(PORT, () => {
  console.log('================================');
  console.log('  ⚡ Hustl Backend is running!');
  console.log('================================');
  console.log(`  URL  →  http://localhost:${PORT}`);
});