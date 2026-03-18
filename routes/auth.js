const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { generateToken, verifyToken } = require('../middleware/auth');

const router = express.Router();

// In-memory user store (replace with DB in production)
const USERS = [
  {
    id: 'admin-001',
    username: 'admin',
    password: bcrypt.hashSync('Admin@Sentinel2024!', 10),
    name: 'Platform Administrator',
    email: 'admin@sentinel.local',
    phone: '',
    role: 'admin',
    team: 'both',
    provider: 'local',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    active: true
  },
  {
    id: 'red-001',
    username: 'redteam',
    password: bcrypt.hashSync('redteam123', 10),
    name: 'Red Team Operator',
    email: 'redteam@sentinel.local',
    phone: '',
    role: 'operator',
    team: 'red',
    provider: 'local',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    active: true
  },
  {
    id: 'blue-001',
    username: 'blueteam',
    password: bcrypt.hashSync('blueteam123', 10),
    name: 'Blue Team Analyst',
    email: 'blueteam@sentinel.local',
    phone: '',
    role: 'analyst',
    team: 'blue',
    provider: 'local',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    active: true
  }
];

const safeUser = (u) => ({
  id: u.id, username: u.username, name: u.name,
  email: u.email, phone: u.phone, role: u.role,
  team: u.team, provider: u.provider, createdAt: u.createdAt,
  lastLogin: u.lastLogin, active: u.active
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = USERS.find(u => u.username === username.toLowerCase() || u.email === username.toLowerCase());
  if (!user || !user.active) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  user.lastLogin = new Date().toISOString();
  const token = generateToken(user);
  res.json({ token, user: safeUser(user) });
});

// POST /api/auth/register
router.post('/register', async (req, res) => {
  const { username, password, name, email, phone } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Username, password and email are required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const exists = USERS.find(u => u.username === username.toLowerCase() || u.email === email.toLowerCase());
  if (exists) return res.status(409).json({ error: 'Username or email already exists' });

  const newUser = {
    id: uuidv4(),
    username: username.toLowerCase(),
    password: await bcrypt.hash(password, 10),
    name: name || username,
    email: email.toLowerCase(),
    phone: phone || '',
    role: 'analyst',
    team: 'blue',
    provider: 'local',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    active: true
  };

  USERS.push(newUser);
  const token = generateToken(newUser);
  res.status(201).json({ token, user: safeUser(newUser) });
});

// GET /api/auth/me
router.get('/me', verifyToken, (req, res) => {
  const user = USERS.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: safeUser(user) });
});

// GET /api/auth/users (admin only)
router.get('/users', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  res.json(USERS.map(safeUser));
});

// PUT /api/auth/users/:id (admin only)
router.put('/users/:id', verifyToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const user = USERS.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { role, team, active, name } = req.body;
  if (role) user.role = role;
  if (team) user.team = team;
  if (active !== undefined) user.active = active;
  if (name) user.name = name;

  res.json({ user: safeUser(user) });
});

// DELETE /api/auth/users/:id (admin only)
router.delete('/users/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const idx = USERS.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (USERS[idx].role === 'admin') return res.status(400).json({ error: 'Cannot delete admin' });
  USERS.splice(idx, 1);
  res.json({ message: 'User deleted' });
});

// Export users list for admin panel
router.getUsers = () => USERS.map(safeUser);

module.exports = router;
module.exports.USERS = USERS;
