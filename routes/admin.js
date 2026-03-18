const express = require('express');
const router = express.Router();

const activityLog = [];

// Middleware - admin only
router.use((req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
});

// GET /api/admin/stats
router.get('/stats', (req, res) => {
  const { USERS } = require('./auth');
  res.json({
    totalUsers: USERS.length,
    activeUsers: USERS.filter(u => u.active).length,
    redTeamUsers: USERS.filter(u => u.team === 'red').length,
    blueTeamUsers: USERS.filter(u => u.team === 'blue').length,
    totalScans: activityLog.length,
    recentActivity: activityLog.slice(0, 20)
  });
});

// GET /api/admin/users
router.get('/users', (req, res) => {
  const { USERS } = require('./auth');
  res.json(USERS.map(u => ({
    id: u.id, username: u.username, name: u.name,
    email: u.email, phone: u.phone, role: u.role,
    team: u.team, provider: u.provider,
    createdAt: u.createdAt, lastLogin: u.lastLogin, active: u.active
  })));
});

// POST /api/admin/log
router.post('/log', (req, res) => {
  activityLog.unshift({
    ...req.body,
    user: req.user.username,
    team: req.user.team,
    timestamp: new Date().toISOString()
  });
  if (activityLog.length > 500) activityLog.pop();
  res.json({ ok: true });
});

// GET /api/admin/activity
router.get('/activity', (req, res) => {
  res.json(activityLog.slice(0, 100));
});

module.exports = router;
module.exports.activityLog = activityLog;
