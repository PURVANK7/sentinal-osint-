const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'sentinel-v2-secret-key-2024';

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username, name: user.name, role: user.role, team: user.team, email: user.email },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
};

module.exports = { verifyToken, generateToken };
