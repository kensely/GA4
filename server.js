/**
 * GA4 分析後端 — OAuth 版本
 * 使用個人 Google 帳號（milk3233@gmail.com）登入授權
 * 適合部署在 Render.com
 */

const express = require('express');
const cors = require('cors');
const https = require('https');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// ── 設定 ──────────────────────────────────────────────────
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:8080/auth/callback';
const GA4_PROPERTY_ID = process.env.GA4_PROPERTY_ID || '209293188';
const PORT = process.env.PORT || 8080;

// ── Token 存儲（記憶體，重啟後需重新登入）────────────────
let tokenStore = { access_token: null, refresh_token: null, expiry: 0 };

// ── HTTPS 工具 ────────────────────────────────────────────
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

// ── OAuth 流程 ────────────────────────────────────────────
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
    code,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    grant_type: 'authorization_code',
  }).toString();

  try {
    const data = await httpsRequest({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, body);

    if (data.access_token) {
      tokenStore = {
        access_token: data.access_token,
        refresh_token: data.refresh_token || tokenStore.refresh_token,
        expiry: Date.now() + (data.expires_in - 60) * 1000,
      };
      res.redirect('/?auth=success');
    } else {
      res.status(400).send(`授權失敗: ${JSON.stringify(data)}`);
    }
  } catch (e) {
    res.status(500).send(`錯誤: ${e.message}`);
  }
});

app.get('/auth/status', (req, res) => {
  res.json({ loggedIn: !!(tokenStore.access_token && Date.now() < tokenStore.expiry) });
});

// ── 自動 refresh token ────────────────────────────────────
async function getValidToken() {
  if (tokenStore.access_token && Date.now() < tokenStore.expiry) {
    return tokenStore.access_token;
  }
  if (!tokenStore.refresh_token) throw new Error('尚未登入，請先點選「登入 Google」');

  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: tokenStore.refresh_token,
    grant_type: 'refresh_token',
  }).toString();

  const data = await httpsRequest({
    hostname: 'oauth2.googleapis.com',
    path: '/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
    },
  }, body);

  if (!data.access_token) throw new Error('Token 更新失敗');
  tokenStore.access_token = data.access_token;
  tokenStore.expiry = Date.now() + (data.expires_in - 60) * 1000;
  return data.access_token;
}

// ── GA4 API ───────────────────────────────────────────────
app.post('/api/ga4/report', async (req, res) => {
  try {
    const token = await getValidToken();
    const payload = JSON.stringify(req.body);
    const result = await httpsRequest({
      hostname: 'analyticsdata.googleapis.com',
      path: `/v1beta/properties/${GA4_PROPERTY_ID}:runReport`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, payload);
    res.json(result);
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

// ── 健康檢查 ──────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok',
  loggedIn: !!(tokenStore.access_token && Date.now() < tokenStore.expiry),
  propertyId: GA4_PROPERTY_ID,
}));

// ── 前端 ──────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`GA4 分析後端啟動於 port ${PORT}`));
