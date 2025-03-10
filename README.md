# GPT Google OAuth 서버

이 프로젝트는 GPTs에서 Google 서비스(Calendar, Tasks, Gmail, Drive)와 연동할 수 있는 OAuth 서버입니다. Netlify 서버리스 함수를 사용하여 배포됩니다.

## 기능

- Google OAuth 인증
- Google Calendar API 연동
- Google Tasks API 연동
- Gmail API 연동
- Google Drive API 연동
- GPTs 플러그인 지원

## 설치 및 실행

### 로컬 개발 환경 설정

```bash
# 저장소 클론
git clone https://github.com/yourusername/gpt-google-oauth-server.git
cd gpt-google-oauth-server

# 의존성 설치
npm install

# 환경 변수 설정
cp .env.example .env
# .env 파일을 편집하여 Google OAuth 클라이언트 ID와 시크릿 설정

# 개발 서버 실행
npm run dev
```

### 환경 변수

- `GOOGLE_CLIENT_ID`: Google OAuth 클라이언트 ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth 클라이언트 시크릿
- `SESSION_SECRET`: 세션 암호화를 위한 시크릿 키

## 배포

이 프로젝트는 Netlify에 배포됩니다.

```bash
# 빌드
npm run build

# Netlify CLI를 사용한 배포
netlify deploy --prod
```

## GPTs 플러그인 설정

1. GPTs에서 새 플러그인 생성
2. 인증 유형으로 OAuth 선택
3. 인증 URL: `https://yourdomain.netlify.app/.netlify/functions/api/auth/google`
4. 토큰 URL: `https://yourdomain.netlify.app/.netlify/functions/api/auth/google/callback`
5. 스코프: `profile email https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/tasks https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive.file`

## 라이선스

MIT 