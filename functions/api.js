import express from 'express';
import serverless from 'serverless-http';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';

dotenv.config();

const __functionDirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Rate limiting 설정
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // IP당 15분 동안 최대 100개 요청
  standardHeaders: true, // 'RateLimit-*' 헤더 반환
  legacyHeaders: false, // 'X-RateLimit-*' 헤더 비활성화
  message: { error: '너무 많은 요청이 발생했습니다. 잠시 후 다시 시도해주세요.' },
  skip: (req) => {
    // 인증 관련 경로는 rate limit에서 제외
    return req.path.startsWith('/auth/');
  }
});

// 인증 경로에 대한 별도의 rate limiter
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1시간
  max: 10, // IP당 1시간 동안 최대 10개 요청
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: '너무 많은 인증 요청이 발생했습니다. 1시간 후 다시 시도해주세요.' }
});

// OAuth2 클라이언트 생성
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  "/.netlify/functions/api/auth/google/callback"
);

// 토큰 리프레시 함수
async function refreshAccessToken(refreshToken) {
  try {
    oauth2Client.setCredentials({
      refresh_token: refreshToken
    });
    
    const { credentials } = await oauth2Client.refreshAccessToken();
    return credentials;
  } catch (error) {
    console.error('토큰 리프레시 오류:', error);
    throw new Error('인증 토큰을 갱신하는 데 실패했습니다.');
  }
}

// 토큰 검증 및 리프레시 미들웨어
const tokenMiddleware = async (req, res, next) => {
  try {
    // 인증 헤더 확인
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: '인증 토큰이 필요합니다.' });
    }

    // 리프레시 토큰 확인
    const refreshToken = req.headers['x-refresh-token'];
    if (!refreshToken) {
      return res.status(401).json({ error: '리프레시 토큰이 필요합니다.' });
    }

    // 토큰 검증 시도
    try {
      const auth = new google.auth.OAuth2();
      auth.setCredentials({ access_token: authHeader });
      
      // 토큰 검증을 위한 간단한 API 호출
      const tokenInfo = await auth.getTokenInfo(authHeader);
      
      // 토큰이 유효하면 다음 미들웨어로 진행
      req.auth = auth;
      next();
    } catch (error) {
      // 토큰이 만료되었거나 유효하지 않은 경우
      if (error.code === 401 || error.message.includes('invalid_token')) {
        try {
          // 리프레시 토큰으로 새 액세스 토큰 발급
          const credentials = await refreshAccessToken(refreshToken);
          
          // 새 토큰으로 인증 객체 설정
          const auth = new google.auth.OAuth2();
          auth.setCredentials({ 
            access_token: credentials.access_token,
            refresh_token: refreshToken
          });
          
          // 새 토큰을 응답 헤더에 추가
          res.setHeader('x-new-access-token', credentials.access_token);
          
          // 인증 객체를 요청에 저장
          req.auth = auth;
          next();
        } catch (refreshError) {
          return res.status(401).json({ error: '인증이 만료되었습니다. 다시 로그인해주세요.' });
        }
      } else {
        return res.status(401).json({ error: '유효하지 않은 인증 토큰입니다.' });
      }
    }
  } catch (error) {
    return res.status(500).json({ error: '인증 처리 중 오류가 발생했습니다.' });
  }
};

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

// API 경로에 rate limiter 적용
app.use('/api', apiLimiter);

// 인증 경로에 rate limiter 적용
app.use('/auth', authLimiter);

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
app.get('/api/calendar/events', tokenMiddleware, async (req, res, next) => {
  try {
    const { calendar } = createGoogleClient(req.auth);
    const events = await calendar.events.list({
      calendarId: 'primary',
      timeMin: new Date().toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: 'startTime',
    });
    
    res.json(events.data);
  } catch (error) {
    next(error);
  }
});

app.post('/api/calendar/events', tokenMiddleware, async (req, res, next) => {
  try {
    const { calendar } = createGoogleClient(req.auth);
    const event = await calendar.events.insert({
      calendarId: 'primary',
      requestBody: req.body
    });
    
    res.json(event.data);
  } catch (error) {
    next(error);
  }
});

// Tasks API Routes
app.get('/api/tasks/lists', tokenMiddleware, async (req, res, next) => {
  try {
    const { tasks } = createGoogleClient(req.auth);
    const taskLists = await tasks.tasklists.list();
    
    res.json(taskLists.data);
  } catch (error) {
    next(error);
  }
});

// Gmail API Routes
app.get('/api/gmail/messages', tokenMiddleware, async (req, res, next) => {
  try {
    const { gmail } = createGoogleClient(req.auth);
    const messages = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 10
    });
    
    res.json(messages.data);
  } catch (error) {
    next(error);
  }
});

// Drive API Routes
app.get('/api/drive/files', tokenMiddleware, async (req, res, next) => {
  try {
    const { drive } = createGoogleClient(req.auth);
    const files = await drive.files.list({
      pageSize: 10,
      fields: 'nextPageToken, files(id, name, mimeType)'
    });
    
    res.json(files.data);
  } catch (error) {
    next(error);
  }
});

// 에러 처리 미들웨어
const errorHandler = (err, req, res, next) => {
  console.error('API 오류:', err);
  
  // 에러 메시지에서 민감한 정보 제거
  let errorMessage = '서버 오류가 발생했습니다.';
  
  if (err.name === 'ValidationError') {
    errorMessage = '입력 데이터가 유효하지 않습니다.';
    return res.status(400).json({ error: errorMessage });
  }
  
  if (err.name === 'UnauthorizedError' || err.status === 401) {
    errorMessage = '인증에 실패했습니다.';
    return res.status(401).json({ error: errorMessage });
  }
  
  if (err.name === 'ForbiddenError' || err.status === 403) {
    errorMessage = '접근 권한이 없습니다.';
    return res.status(403).json({ error: errorMessage });
  }
  
  if (err.name === 'NotFoundError' || err.status === 404) {
    errorMessage = '요청한 리소스를 찾을 수 없습니다.';
    return res.status(404).json({ error: errorMessage });
  }
  
  // 개발 환경에서만 상세 에러 메시지 표시
  if (process.env.NODE_ENV === 'development') {
    errorMessage = err.message || errorMessage;
  }
  
  res.status(500).json({ error: errorMessage });
};

// 에러 핸들러 등록
app.use(errorHandler);

// Export the serverless function
export const handler = serverless(app); 