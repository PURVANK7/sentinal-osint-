const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;

module.exports = (passport) => {
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  // Google OAuth
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.BASE_URL + '/auth/google/callback'
    }, (accessToken, refreshToken, profile, done) => {
      const user = {
        id: 'google_' + profile.id,
        username: profile.emails[0].value.split('@')[0],
        name: profile.displayName,
        email: profile.emails[0].value,
        role: 'analyst',
        team: 'blue',
        avatar: profile.photos[0]?.value,
        provider: 'google'
      };
      return done(null, user);
    }));
  }

  // Facebook OAuth
  if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.BASE_URL + '/auth/facebook/callback',
      profileFields: ['id', 'displayName', 'emails', 'photos']
    }, (accessToken, refreshToken, profile, done) => {
      const user = {
        id: 'fb_' + profile.id,
        username: profile.displayName.replace(/\s+/g, '').toLowerCase(),
        name: profile.displayName,
        email: profile.emails?.[0]?.value || '',
        role: 'analyst',
        team: 'blue',
        provider: 'facebook'
      };
      return done(null, user);
    }));
  }

  // LinkedIn OAuth
  if (process.env.LINKEDIN_CLIENT_ID && process.env.LINKEDIN_CLIENT_SECRET) {
    passport.use(new LinkedInStrategy({
      clientID: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      callbackURL: process.env.BASE_URL + '/auth/linkedin/callback',
      scope: ['r_emailaddress', 'r_liteprofile']
    }, (accessToken, refreshToken, profile, done) => {
      const user = {
        id: 'li_' + profile.id,
        username: profile.emails[0].value.split('@')[0],
        name: profile.displayName,
        email: profile.emails[0].value,
        role: 'analyst',
        team: 'blue',
        provider: 'linkedin'
      };
      return done(null, user);
    }));
  }
};
