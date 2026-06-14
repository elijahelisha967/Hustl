const express  = require('express');
const path     = require('path');
const bcrypt   = require('bcryptjs');
const mongoose = require('mongoose');
const jwt      = require('jsonwebtoken');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'hustl_secret_key_change_in_prod';

// MongoDB connection (cached for serverless)
let isConnected = false;
async function connectDB() {
  if (isConnected) return;
  await mongoose.connect(process.env.MONGODB_URI);
  isConnected = true;
}

// ── USER SCHEMA ──
const userSchema = new mongoose.Schema({
  id:           { type: Number, unique: true },
  name:         String,
  email:        { type: String, unique: true, lowercase: true },
  role:         String,
  passwordHash: String,
  dateJoined:   { type: Date, default: Date.now },

  // Onboarding fields
  school:             String,
  department:         String,
  yearOfStudy:        String,
  skills:             [String],
  bankName:           String,
  accountNumber:      String,
  accountName:        String,
  profilePhoto:       String,
  onboardingComplete: { type: Boolean, default: false }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

// ── CORS ──
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ──
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No token provided.' });
  }
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── HEALTH CHECK ──
app.get('/api', (req, res) => {
  res.json({ message: '⚡ Hustl API is running!' });
});

// ── SIGNUP ──
app.post('/api/signup', async (req, res) => {
  try {
    await connectDB();

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

    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) {
      return res.status(409).json({
        success: false,
        message: 'Email already registered.',
        errors: { email: 'This email already exists.' }
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({
      id: Date.now(),
      name,
      email: email.toLowerCase(),
      role,
      passwordHash
    });
    await newUser.save();

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.status(201).json({
      success: true,
      message: `Welcome to Hustl, ${newUser.name}!`,
      token,
      user: {
        id:                 newUser.id,
        name:               newUser.name,
        email:              newUser.email,
        role:               newUser.role,
        onboardingComplete: newUser.onboardingComplete,
        dateJoined:         newUser.dateJoined
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  try {
    await connectDB();

    const email    = (req.body.email    || '').trim().toLowerCase();
    const password = (req.body.password || '').trim();

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
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

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      success: true,
      message: `Welcome back, ${user.name}!`,
      token,
      user: {
        id:                 user.id,
        name:               user.name,
        email:              user.email,
        role:               user.role,
        onboardingComplete: user.onboardingComplete
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── ONBOARDING (PATCH) ──
app.patch('/api/users/onboarding', authMiddleware, async (req, res) => {
  try {
    await connectDB();

    const {
      school, department, yearOfStudy, skills,
      bankName, accountNumber, accountName, profilePhoto
    } = req.body;

    const updated = await User.findOneAndUpdate(
      { id: req.user.id },
      {
        $set: {
          school, department, yearOfStudy,
          skills:             skills || [],
          bankName,           accountNumber, accountName,
          profilePhoto:       profilePhoto || '',
          onboardingComplete: true
        }
      },
      { new: true, select: '-passwordHash' }
    );

    if (!updated) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    return res.json({ success: true, message: 'Profile saved!', user: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── GET PROFILE ──
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    await connectDB();
    const user = await User.findOne({ id: req.user.id }, '-passwordHash');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    return res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── GET ALL USERS ──
app.get('/api/users', async (req, res) => {
  try {
    await connectDB();
    const users = await User.find({}, '-passwordHash');
    return res.json({ success: true, total: users.length, users });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── GET USER BY ID ──
app.get('/api/users/:id', async (req, res) => {
  try {
    await connectDB();
    const user = await User.findOne({ id: Number(req.params.id) }, '-passwordHash');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    return res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── DELETE USER ──
app.delete('/api/users/:id', async (req, res) => {
  try {
    await connectDB();
    const user = await User.findOneAndDelete({ id: Number(req.params.id) });
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
    return res.json({ success: true, message: `${user.name} removed.` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// For local development
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log('================================');
    console.log('  ⚡ Hustl Backend is running!');
    console.log('================================');
    console.log(`  URL  →  http://localhost:${PORT}`);
  });
}

module.exports = app;