const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'hustl_secret_key_change_in_prod';

let isConnected = false;
async function connectDB() {
  if (isConnected) return;
  await mongoose.connect(process.env.MONGODB_URI);
  isConnected = true;
}

const userSchema = new mongoose.Schema({
  id: { type: Number, unique: true },
  name: String,
  email: { type: String, unique: true, lowercase: true },
  role: String,
  passwordHash: String,
  dateJoined: { type: Date, default: Date.now },
  school: String, department: String, yearOfStudy: String,
  skills: [String], bankName: String, accountNumber: String,
  accountName: String, profilePhoto: String,
  onboardingComplete: { type: Boolean, default: false }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, message: 'Method not allowed' });

  try {
    await connectDB();
    const name = (req.body.name || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const role = (req.body.role || '').trim().toLowerCase();
    const password = (req.body.password || '').trim();

    const errors = {};
    if (!name || name.length < 2) errors.name = 'Name is required.';
    if (!email) errors.email = 'Email is required.';
    if (!password || password.length < 6) errors.password = 'Password must be at least 6 characters.';
    if (!['student', 'business'].includes(role)) errors.role = 'Invalid role.';
    if (Object.keys(errors).length > 0) return res.status(400).json({ success: false, errors });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ success: false, message: 'Email already registered.', errors: { email: 'This email already exists.' } });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ id: Date.now(), name, email, role, passwordHash });
    await newUser.save();

    const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '7d' });

    return res.status(201).json({
      success: true,
      message: `Welcome to Hustl, ${newUser.name}!`,
      token,
      data: { user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role, onboardingComplete: false } }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
};