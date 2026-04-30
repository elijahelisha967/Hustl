const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Manual CORS — fixes Railway preflight 502
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'data', 'users.json');

function readUsers() {
  if (!fs.existsSync(DB_FILE)) return [];
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
}

function saveUsers(users) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get('/', (req, res) => {
  res.json({ message: '⚡ Hustl API is running!' });
});

app.post('/signup', async (req, res) => {
  const name     = (req.body.name     || '').trim();
  const email    = (req.body.email    || '').trim();
  const role     = (req.body.role     || '').trim().toLowerCase();
  const password = (req.body.password || '').trim();

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

  const users = readUsers();
  const exists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (exists) {
    return res.status(409).json({
      success: false,
      message: 'Email already registered.',
      errors: { email: 'This email already exists.' }
    });
  }

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

app.post('/login', async (req, res) => {
  const email    = (req.body.email    || '').trim().toLowerCase();
  const password = (req.body.password || '').trim();

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'No account found with this email.',
      errors: { email: 'No account found with this email.' }
    });
  }

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.status(401).json({
      success: false,
      message: 'Incorrect password.',
      errors: { password: 'Incorrect password. Try again.' }
    });
  }

  return res.json({
    success: true,
    message: `Welcome back, ${user.name}!`,
    user: { id: user.id, name: user.name, email: user.email, role: user.role }
  });
});

app.get('/users', (req, res) => {
  const users = readUsers();
  const safe = users.map(({ passwordHash, ...rest }) => rest);
  return res.json({ success: true, total: safe.length, users: safe });
});

app.get('/users/:id', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === Number(req.params.id));
  if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
  const { passwordHash, ...safe } = user;
  return res.json({ success: true, user: safe });
});

app.delete('/users/:id', (req, res) => {
  const users = readUsers();
  const index = users.findIndex(u => u.id === Number(req.params.id));
  if (index === -1) return res.status(404).json({ success: false, message: 'User not found.' });
  const removed = users.splice(index, 1)[0];
  saveUsers(users);
  return res.json({ success: true, message: `${removed.name} removed.` });
});

app.listen(PORT, () => {
  console.log('================================');
  console.log('  ⚡ Hustl Backend is running!');
  console.log('================================');
  console.log(`  URL  →  http://localhost:${PORT}`);
});