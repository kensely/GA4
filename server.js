/**
 * GA4 分析後端 — OAuth + Cookie Session + Anthropic Proxy 版本
 */

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
  const isHttps = REDIRECT_URI && REDIRECT_URI.startsWith('https');
  const secureFlag = isHttps ? '; Secure' : '';
  res.setHeader('Set-Cookie', `session=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secureFlag}`);
  return sid;
}

function httpsRequest(hostname, reqPath, method, headers, body) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path: reqPath, method, headers }, res => {
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

// ── OAuth ─────────────────────────────────────────────────
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
    const data = await httpsRequest('oauth2.googleapis.com', '/token', 'POST', {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
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
  if (!session) throw new Error('尚未登入');
  if (session.access_token && Date.now() < session.expiry) return session.access_token;
  if (!session.refresh_token) throw new Error('請重新登入');
  const body = new URLSearchParams({
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    refresh_token: session.refresh_token, grant_type: 'refresh_token',
  }).toString();
  const data = await httpsRequest('oauth2.googleapis.com', '/token', 'POST', {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(body),
  }, body);
  if (!data.access_token) throw new Error('Token 更新失敗');
  session.access_token = data.access_token;
  session.expiry = Date.now() + (data.expires_in - 60) * 1000;
  return data.access_token;
}

// ── GA4 API ───────────────────────────────────────────────
app.post('/api/ga4/report', async (req, res) => {
  try {
    const token = await getValidToken(req);
    const payload = JSON.stringify(req.body);
    const result = await httpsRequest('analyticsdata.googleapis.com',
      `/v1beta/properties/${GA4_PROPERTY_ID}:runReport`, 'POST', {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      }, payload);
    res.json(result);
  } catch (e) { res.status(401).json({ error: e.message }); }
});

// ── Anthropic API Proxy ───────────────────────────────────
app.post('/api/ask', async (req, res) => {
  try {
    const { messages, system } = req.body;
    const payload = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      system,
      messages,
    });
    const result = await httpsRequest('api.anthropic.com', '/v1/messages', 'POST', {
      'x-api-key': ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    }, payload);
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 健康檢查 + 前端 ───────────────────────────────────────
app.get('/health', (req, res) => {
  const session = getSession(req);
  res.json({ status: 'ok', loggedIn: !!(session && session.access_token), propertyId: GA4_PROPERTY_ID });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`GA4 分析後端啟動於 port ${PORT}`));
