import express from 'express';
import serverless from 'serverless-http';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import path from 'path';
// import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import cors from 'cors';

dotenv.config();

// Netlify 서버리스 함수 환경에서는 import.meta.url이 작동하지 않으므로 제거
// const __functionDirname = path.dirname(fileURLToPath(import.meta.url));
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
  "https://ucandoai.netlify.app/.netlify/functions/api/auth/google/callback"
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
    // 인증 헤더 확인 (Bearer 토큰 또는 일반 토큰)
    let accessToken = null;
    const authHeader = req.headers.authorization;
    
    if (authHeader) {
      // Bearer 토큰 형식인 경우 (Bearer xxxxx)
      if (authHeader.startsWith('Bearer ')) {
        accessToken = authHeader.substring(7);
      } else {
        // 일반 토큰인 경우
        accessToken = authHeader;
      }
    } else if (req.query.access_token) {
      // 쿼리 파라미터로 전달된 경우
      accessToken = req.query.access_token;
    } else if (req.body && req.body.access_token) {
      // 요청 본문으로 전달된 경우
      accessToken = req.body.access_token;
    }
    
    if (!accessToken) {
      console.error('인증 토큰 없음');
      return res.status(401).json({ error: '인증 토큰이 필요합니다.' });
    }
    
    // 리프레시 토큰 확인 (여러 소스에서 확인)
    let refreshToken = null;
    if (req.headers['x-refresh-token']) {
      refreshToken = req.headers['x-refresh-token'];
    } else if (req.query.refresh_token) {
      refreshToken = req.query.refresh_token;
    } else if (req.body && req.body.refresh_token) {
      refreshToken = req.body.refresh_token;
    }
    
    // 디버깅을 위한 로그
    console.log('토큰 정보:', {
      hasAccessToken: !!accessToken,
      accessTokenPrefix: accessToken ? accessToken.substring(0, 10) + '...' : null,
      hasRefreshToken: !!refreshToken,
      refreshTokenPrefix: refreshToken ? refreshToken.substring(0, 10) + '...' : null,
      headers: Object.keys(req.headers),
      query: Object.keys(req.query),
      body: req.body ? Object.keys(req.body) : null,
      path: req.path
    });

    // 토큰 검증 시도
    try {
      const auth = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        "https://ucandoai.netlify.app/.netlify/functions/api/auth/google/callback"
      );
      
      // 액세스 토큰 설정
      auth.setCredentials({ 
        access_token: accessToken,
        refresh_token: refreshToken
      });
      
      // 토큰이 유효하면 다음 미들웨어로 진행
      req.auth = auth;
      
      // 토큰 정보를 응답 헤더에 추가 (디버깅용)
      res.setHeader('x-debug-access-token', accessToken.substring(0, 10) + '...');
      if (refreshToken) {
        res.setHeader('x-debug-refresh-token', refreshToken.substring(0, 10) + '...');
      }
      
      next();
    } catch (error) {
      console.error('토큰 검증 오류:', error);
      
      // 토큰이 만료되었거나 유효하지 않은 경우
      if (error.code === 401 || error.message.includes('invalid_token')) {
        if (!refreshToken) {
          return res.status(401).json({ 
            error: '인증이 만료되었습니다. 리프레시 토큰이 필요합니다.',
            code: 'TOKEN_EXPIRED_NO_REFRESH'
          });
        }
        
        try {
          // 리프레시 토큰으로 새 액세스 토큰 발급
          const credentials = await refreshAccessToken(refreshToken);
          
          // 새 토큰으로 인증 객체 설정
          const auth = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            "https://ucandoai.netlify.app/.netlify/functions/api/auth/google/callback"
          );
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
          console.error('토큰 리프레시 오류:', refreshError);
          return res.status(401).json({ 
            error: '인증이 만료되었습니다. 다시 로그인해주세요.',
            code: 'TOKEN_REFRESH_FAILED'
          });
        }
      } else {
        return res.status(401).json({ 
          error: '유효하지 않은 인증 토큰입니다.',
          code: 'INVALID_TOKEN'
        });
      }
    }
  } catch (error) {
    console.error('인증 처리 중 오류:', error);
    return res.status(500).json({ 
      error: '인증 처리 중 오류가 발생했습니다.',
      code: 'AUTH_PROCESSING_ERROR'
    });
  }
};

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://ucandoai.netlify.app/.netlify/functions/api/auth/google/callback"
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
app.use(cors({
  origin: ['https://chat.openai.com', 'https://ucandoai.netlify.app', '*'], // OpenAI GPTs 및 모든 도메인에서의 요청 허용
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Refresh-Token'],
  exposedHeaders: ['X-New-Access-Token'],
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(passport.initialize());
app.use(passport.session());

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

// Netlify 서버리스 함수에서 경로 접두사 설정
const router = express.Router();
app.use('/.netlify/functions/api', router);

// Routes
router.get('/', (req, res) => {
  res.send('GPT Google OAuth Server');
});

router.get('/auth/google',
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

router.get('/auth/google/callback', 
  function(req, res, next) {
    passport.authenticate('google', function(err, user, info) {
      if (err) {
        console.error('OAuth 콜백 오류:', err);
        return res.status(500).json({ error: '인증 과정에서 오류가 발생했습니다.', details: err.message });
      }
      
      if (!user) {
        console.error('사용자 인증 실패:', info);
        return res.status(401).json({ error: '사용자 인증에 실패했습니다.' });
      }
      
      req.logIn(user, function(err) {
        if (err) {
          console.error('로그인 오류:', err);
          return res.status(500).json({ error: '로그인 과정에서 오류가 발생했습니다.', details: err.message });
        }
        
        // 디버깅을 위한 로그
        console.log('인증 성공:', {
          userId: user.profile.id,
          email: user.profile.emails?.[0]?.value,
          hasAccessToken: !!user.accessToken,
          hasRefreshToken: !!user.refreshToken
        });
        
        // OpenAI GPTs에서 기대하는 응답 형식
        const response = {
          access_token: user.accessToken,
          refresh_token: user.refreshToken,
          token_type: "Bearer",
          expires_in: 3600 // 1시간
        };
        
        // Content-Type 헤더 설정
        res.setHeader('Content-Type', 'application/json');
        
        // 응답 반환
        return res.json(response);
      });
    })(req, res, next);
  }
);

// 기존 라우트도 유지 (하위 호환성을 위해)
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
  function(req, res, next) {
    passport.authenticate('google', function(err, user, info) {
      if (err) {
        console.error('OAuth 콜백 오류:', err);
        return res.status(500).json({ error: '인증 과정에서 오류가 발생했습니다.', details: err.message });
      }
      
      if (!user) {
        console.error('사용자 인증 실패:', info);
        return res.status(401).json({ error: '사용자 인증에 실패했습니다.' });
      }
      
      req.logIn(user, function(err) {
        if (err) {
          console.error('로그인 오류:', err);
          return res.status(500).json({ error: '로그인 과정에서 오류가 발생했습니다.', details: err.message });
        }
        
        // 디버깅을 위한 로그
        console.log('인증 성공:', {
          userId: user.profile.id,
          email: user.profile.emails?.[0]?.value,
          hasAccessToken: !!user.accessToken,
          hasRefreshToken: !!user.refreshToken
        });
        
        // OpenAI GPTs에서 기대하는 응답 형식
        const response = {
          access_token: user.accessToken,
          refresh_token: user.refreshToken,
          token_type: "Bearer",
          expires_in: 3600 // 1시간
        };
        
        // Content-Type 헤더 설정
        res.setHeader('Content-Type', 'application/json');
        
        // 응답 반환
        return res.json(response);
      });
    })(req, res, next);
  }
);

// Calendar API Routes
router.get('/api/calendar/events', tokenMiddleware, async (req, res, next) => {
  try {
    console.log('캘린더 이벤트 요청 처리 중...');
    const { calendar } = createGoogleClient(req.auth);
    const events = await calendar.events.list({
      calendarId: 'primary',
      timeMin: new Date().toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: 'startTime',
    });
    
    console.log('캘린더 이벤트 조회 성공:', events.data.items?.length || 0);
    res.json(events.data);
  } catch (error) {
    console.error('캘린더 이벤트 조회 오류:', error);
    next(error);
  }
});

router.post('/api/calendar/events', tokenMiddleware, async (req, res, next) => {
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
router.get('/api/tasks/lists', tokenMiddleware, async (req, res, next) => {
  try {
    const { tasks } = createGoogleClient(req.auth);
    const taskLists = await tasks.tasklists.list();
    
    res.json(taskLists.data);
  } catch (error) {
    next(error);
  }
});

// Gmail API Routes
router.get('/api/gmail/messages', tokenMiddleware, async (req, res, next) => {
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
router.get('/api/drive/files', tokenMiddleware, async (req, res, next) => {
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

// 테스트 엔드포인트 추가
router.get('/test', (req, res) => {
  res.json({
    message: '서버가 정상적으로 작동 중입니다.',
    timestamp: new Date().toISOString()
  });
});

// 토큰 테스트 엔드포인트 추가
router.get('/test/token', tokenMiddleware, (req, res) => {
  res.json({
    message: '토큰이 유효합니다.',
    timestamp: new Date().toISOString(),
    tokenInfo: {
      hasAuth: !!req.auth,
      hasAccessToken: !!req.auth.credentials.access_token,
      hasRefreshToken: !!req.auth.credentials.refresh_token
    }
  });
});

// 사용자 정보 엔드포인트 추가
router.get('/api/user/profile', tokenMiddleware, async (req, res, next) => {
  try {
    console.log('사용자 프로필 요청 처리 중...');
    const oauth2 = google.oauth2({
      auth: req.auth,
      version: 'v2'
    });
    
    const userInfo = await oauth2.userinfo.get();
    console.log('사용자 프로필 조회 성공');
    res.json(userInfo.data);
  } catch (error) {
    console.error('사용자 프로필 조회 오류:', error);
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