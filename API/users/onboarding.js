const mongoose = require('mongoose');
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
  school: String,
  department: String,
  yearOfStudy: String,
  skills: [String],
  bankName: String,
  accountNumber: String,
  accountName: String,
  profilePhoto: String,
  onboardingComplete: { type: Boolean, default: false }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'PATCH') return res.status(405).json({ success: false, message: 'Method not allowed' });

  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No token provided.' });
  }

  let decoded;
  try {
    decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token.' });
  }

  try {
    await connectDB();
    const { school, department, yearOfStudy, skills, bankName, accountNumber, accountName, profilePhoto } = req.body;

    const updated = await User.findOneAndUpdate(
      { id: decoded.id },
      { $set: { school, department, yearOfStudy, skills: skills || [], bankName, accountNumber, accountName, profilePhoto: profilePhoto || '', onboardingComplete: true } },
      { new: true, select: '-passwordHash' }
    );

    if (!updated) return res.status(404).json({ success: false, message: 'User not found.' });
    return res.json({ success: true, message: 'Profile saved!', user: updated });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
};