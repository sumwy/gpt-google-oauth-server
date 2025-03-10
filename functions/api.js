import express from 'express';
import serverless from 'serverless-http';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/.netlify/functions/api/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    return cb(null, {
      profile,
      accessToken,
      refreshToken
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware
app.use(express.json());
app.use(passport.initialize());

// Create Google API client
const createGoogleClient = (auth) => {
  return {
    calendar: google.calendar({ version: 'v3', auth }),
    tasks: google.tasks({ version: 'v1', auth }),
    gmail: google.gmail({ version: 'v1', auth }),
    drive: google.drive({ version: 'v3', auth })
  };
};

// Routes
app.get('/', (req, res) => {
  res.send('GPT Google OAuth Server');
});

app.get('/auth/google',
  passport.authenticate('google', { 
    scope: [
      'profile',
      'email',
      'https://www.googleapis.com/auth/calendar',
      'https://www.googleapis.com/auth/tasks',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/drive.file'
    ],
    accessType: 'offline',
    prompt: 'consent'
  })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    const tokens = {
      accessToken: req.user.accessToken,
      refreshToken: req.user.refreshToken
    };
    res.json(tokens);
  }
);

// Calendar API Routes
app.get('/api/calendar/events', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { calendar } = createGoogleClient(auth);
    const events = await calendar.events.list({
      calendarId: 'primary',
      timeMin: new Date().toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: 'startTime',
    });
    
    res.json(events.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/calendar/events', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { calendar } = createGoogleClient(auth);
    const event = await calendar.events.insert({
      calendarId: 'primary',
      requestBody: req.body
    });
    
    res.json(event.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tasks API Routes
app.get('/api/tasks/lists', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { tasks } = createGoogleClient(auth);
    const taskLists = await tasks.tasklists.list();
    
    res.json(taskLists.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Gmail API Routes
app.get('/api/gmail/messages', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { gmail } = createGoogleClient(auth);
    const messages = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 10
    });
    
    res.json(messages.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Drive API Routes
app.get('/api/drive/files', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { drive } = createGoogleClient(auth);
    const files = await drive.files.list({
      pageSize: 10,
      fields: 'nextPageToken, files(id, name, mimeType)'
    });
    
    res.json(files.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Export the serverless function
export const handler = serverless(app); 