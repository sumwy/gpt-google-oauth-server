import express from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
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

// Serve .well-known directory for GPT plugin discovery
app.use('/.well-known', express.static(path.join(__dirname, '.well-known')));

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

app.put('/api/calendar/events/:eventId', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { calendar } = createGoogleClient(auth);
    const event = await calendar.events.update({
      calendarId: 'primary',
      eventId: req.params.eventId,
      requestBody: req.body
    });
    
    res.json(event.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/calendar/events/:eventId', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { calendar } = createGoogleClient(auth);
    await calendar.events.delete({
      calendarId: 'primary',
      eventId: req.params.eventId
    });
    
    res.json({ message: 'Event deleted successfully' });
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

app.post('/api/tasks/lists', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { tasks } = createGoogleClient(auth);
    const taskList = await tasks.tasklists.insert({
      requestBody: req.body
    });
    
    res.json(taskList.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/tasks/lists/:taskListId/tasks', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { tasks } = createGoogleClient(auth);
    const tasksList = await tasks.tasks.list({
      tasklist: req.params.taskListId
    });
    
    res.json(tasksList.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tasks/lists/:taskListId/tasks', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { tasks } = createGoogleClient(auth);
    const task = await tasks.tasks.insert({
      tasklist: req.params.taskListId,
      requestBody: req.body
    });
    
    res.json(task.data);
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
    
    // Fetch full message details for each message
    const fullMessages = await Promise.all(
      messages.data.messages.map(async (message) => {
        const fullMessage = await gmail.users.messages.get({
          userId: 'me',
          id: message.id,
          format: 'full'
        });
        return fullMessage.data;
      })
    );
    
    res.json({ messages: fullMessages });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/gmail/messages', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { gmail } = createGoogleClient(auth);
    const message = await gmail.users.messages.send({
      userId: 'me',
      requestBody: req.body
    });
    
    res.json(message.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/gmail/messages/:messageId', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { gmail } = createGoogleClient(auth);
    await gmail.users.messages.trash({
      userId: 'me',
      id: req.params.messageId
    });
    
    res.json({ message: 'Message moved to trash' });
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
      fields: 'nextPageToken, files(id, name, mimeType, webViewLink, createdTime)'
    });
    
    res.json(files.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/drive/files', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { drive } = createGoogleClient(auth);
    const file = await drive.files.create({
      requestBody: {
        name: req.body.name,
        mimeType: req.body.mimeType
      },
      media: {
        mimeType: req.body.mimeType,
        body: req.body.content
      }
    });
    
    res.json(file.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/drive/files/:fileId', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { drive } = createGoogleClient(auth);
    const file = await drive.files.get({
      fileId: req.params.fileId,
      fields: 'id, name, mimeType, webViewLink, createdTime'
    });
    
    res.json(file.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/drive/files/:fileId', async (req, res) => {
  try {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: req.headers.authorization });
    
    const { drive } = createGoogleClient(auth);
    await drive.files.delete({
      fileId: req.params.fileId
    });
    
    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});