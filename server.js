require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const passport = require('passport');

const authRoutes = require('./routes/auth');
const osintRoutes = require('./routes/osint');
const adminRoutes = require('./routes/admin');
const { verifyToken } = require('./middleware/auth');

// Passport config
require('./middleware/passport')(passport);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session for OAuth
app.use(session({
  secret: process.env.SESSION_SECRET || 'sentinel-session-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/osint', verifyToken, osintRoutes);
app.use('/api/admin', verifyToken, adminRoutes);

// OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/?error=google_failed' }),
  (req, res) => {
    const { generateToken } = require('./middleware/auth');
    const token = generateToken(req.user);
    res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify(req.user))}`);
  }
);

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/?error=fb_failed' }),
  (req, res) => {
    const { generateToken } = require('./middleware/auth');
    const token = generateToken(req.user);
    res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify(req.user))}`);
  }
);

app.get('/auth/linkedin', passport.authenticate('linkedin'));
app.get('/auth/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/?error=linkedin_failed' }),
  (req, res) => {
    const { generateToken } = require('./middleware/auth');
    const token = generateToken(req.user);
    res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify(req.user))}`);
  }
);

// Serve SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🔍 SENTINEL v2 running on port ${PORT}`);
});

module.exports = app;
