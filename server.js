const express = require('express');
const cors = require('cors');
const https = require('https');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:8080/auth/callback';
const GA4_PROPERTY_ID = process.env.GA4_PROPERTY_ID || '209293188';
const ANTHROPIC_KEY = process.env.ANTHROPIC_KEY;
const PORT = process.env.PORT || 8080;

const sessions = {};

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/session=([^;]+)/);
  const sid = match ? match[1] : null;
  return sid ? sessions[sid] : null;
}

function createSession(res, data) {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions[sid] = data;
  const isHttps = process.env.REDIRECT_URI && process.env.REDIRECT_URI.startsWith('https');
  const secureFlag = isHttps ? '; Secure' : '';
  res.setHeader('Set-Cookie', `session=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secureFlag}`);
  return sid;
}

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(data)); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

app.get('/auth/login', (req, res) => {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/analytics.readonly',
    access_type: 'offline',
    prompt: 'consent',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('缺少授權碼');
  const body = new URLSearchParams({
    code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI, grant_type: 'authorization_code',
  }).toString();
  try {
    const data = await httpsRequest({
      hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, body);
    if (data.access_token) {
      createSession(res, {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expiry: Date.now() + (data.expires_in - 60) * 1000,
      });
      res.redirect('/?auth=success');
    } else {
      res.status(400).send(`授權失敗: ${JSON.stringify(data)}`);
    }
  } catch (e) { res.status(500).send(`錯誤: ${e.message}`); }
});

app.get('/auth/status', (req, res) => {
  const session = getSession(req);
  res.json({ loggedIn: !!(session && session.access_token && Date.now() < session.expiry) });
});

async function getValidToken(req) {
  const session = getSession(req);
  if (!session) throw new Error('尚未登入，請先點選「登入 Google」');
  if (session.access_token && Date.now() < session.expiry) return session.access_token;
  if (!session.refresh_token) throw new Error('Session 已過期，請重新登入');
  const body = new URLSearchParams({
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    refresh_token: session.refresh_token, grant_type: 'refresh_token',
  }).toString();
  const data = await httpsRequest({
    hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
  }, body);
  if (!data.access_token) throw new Error('Token 更新失敗，請重新登入');
  session.access_token = data.access_token;
  session.expiry = Date.now() + (data.expires_in - 60) * 1000;
  return data.access_token;
}

// GA4 API
app.post('/api/ga4/report', async (req, res) => {
  try {
    const token = await getValidToken(req);
    const payload = JSON.stringify(req.body);
    const result = await httpsRequest({
      hostname: 'analyticsdata.googleapis.com',
      path: `/v1beta/properties/${GA4_PROPERTY_ID}:runReport`,
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, payload);
    res.json(result);
  } catch (e) { res.status(401).json({ error: e.message }); }
});

// Anthropic API Proxy（解決 CORS 問題）
app.post('/api/ask', async (req, res) => {
  if (!ANTHROPIC_KEY) return res.status(500).json({ error: '請設定 ANTHROPIC_KEY 環境變數' });
  try {
    const payload = JSON.stringify(req.body);
    const result = await httpsRequest({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, payload);
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/health', (req, res) => {
  const session = getSession(req);
  res.json({ status: 'ok', loggedIn: !!(session && session.access_token), propertyId: GA4_PROPERTY_ID });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, () => console.log(`GA4 分析後端啟動於 port ${PORT}`));
