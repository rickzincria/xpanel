require('dotenv').config();
const express = require('express');
const multer  = require('multer');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');h
const https   = require('https');
const http    = require('http');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: 'uploads/', limits: { fileSize: 512 * 1024 * 1024 } });

const accounts  = {};
const pkceStore = {};

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function generatePKCE() {
  const verifier  = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

function apiRequest(method, url, token, body, isFormData) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const headers = { 'Authorization': `Bearer ${token}`, 'User-Agent': 'XPanel/1.0' };
    let postData;
    if (isFormData) {
      Object.assign(headers, body.headers);
      postData = body.data;
    } else if (body) {
      postData = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(postData);
    }
    const options = { hostname: parsed.hostname, path: parsed.pathname + parsed.search, method, headers };
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

function postForm(url, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname, path: parsed.pathname, method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`,
      },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(data); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

app.get('/auth/start', (req, res) => {
  if (!process.env.TWITTER_CLIENT_ID) return res.status(500).json({ error: 'TWITTER_CLIENT_ID nao configurado' });
  const state = base64url(crypto.randomBytes(16));
  const pkce  = generatePKCE();
  pkceStore[state] = { verifier: pkce.verifier };
  const params = new URLSearchParams({
    response_type: 'code', client_id: process.env.TWITTER_CLIENT_ID,
    redirect_uri: process.env.CALLBACK_URL || 'http://localhost:3000/auth/callback',
    scope: 'tweet.read tweet.write users.read offline.access',
    state, code_challenge: pkce.challenge, code_challenge_method: 'S256',
  });
  res.json({ url: `https://twitter.com/i/oauth2/authorize?${params}` });
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect(`/?error=${error}`);
  if (!pkceStore[state]) return res.redirect('/?error=invalid_state');
  const { verifier } = pkceStore[state];
  delete pkceStore[state];
  try {
    const tokenData = await postForm('https://api.twitter.com/2/oauth2/token', {
      grant_type: 'authorization_code', code,
      redirect_uri: process.env.CALLBACK_URL || 'http://localhost:3000/auth/callback',
      client_id: process.env.TWITTER_CLIENT_ID, code_verifier: verifier,
    });
    if (!tokenData.access_token) return res.redirect(`/?error=${JSON.stringify(tokenData)}`);
    const userRes = await apiRequest('GET', 'https://api.twitter.com/2/users/me?user.fields=profile_image_url,name,username', tokenData.access_token);
    const user = userRes.data.data;
    accounts[user.id] = { id: user.id, name: user.name, username: user.username, avatar: user.profile_image_url?.replace('_normal','_bigger'), accessToken: tokenData.access_token, refreshToken: tokenData.refresh_token, addedAt: new Date().toISOString() };
    res.redirect('/?connected=1&user=' + encodeURIComponent(user.username));
  } catch(err) { console.error(err); res.redirect('/?error=token_exchange_failed'); }
});

app.get('/accounts', (req, res) => {
  res.json(Object.values(accounts).map(({ id, name, username, avatar, addedAt }) => ({ id, name, username, avatar, addedAt })));
});

app.delete('/accounts/:id', (req, res) => { delete accounts[req.params.id]; res.json({ ok: true }); });

function uploadBase64Media(token, b64) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({ media_data: b64 }).toString();
    const options = {
      hostname: 'upload.twitter.com', path: '/1.1/media/upload.json', method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    };
    const req = https.request(options, (res) => { let data=''; res.on('data',c=>data+=c); res.on('end',()=>{ try{resolve(JSON.parse(data));}catch{reject(data);} }); });
    req.on('error', reject); req.write(body); req.end();
  });
}

function waitForVideoProcessing(token, mediaId) {
  return new Promise((resolve, reject) => {
    const check = () => {
      const options = { hostname:'upload.twitter.com', path:`/1.1/media/upload.json?command=STATUS&media_id=${mediaId}`, method:'GET', headers:{'Authorization':`Bearer ${token}`} };
      const req = https.request(options, (res) => { let data=''; res.on('data',c=>data+=c); res.on('end',()=>{ try{ const json=JSON.parse(data); const state=json.processing_info?.state; if(state==='succeeded') return resolve(); if(state==='failed') return reject(new Error('Video failed')); setTimeout(check,(json.processing_info?.check_after_secs||5)*1000); }catch{resolve();} }); });
      req.on('error', reject); req.end();
    };
    check();
  });
}

app.post('/upload-media', upload.single('media'), async (req, res) => {
  const { accountId } = req.body;
  const account = accounts[accountId];
  if (!account) return res.status(401).json({ error: 'Conta nao encontrada' });
  const filePath = req.file.path;
  const mimeType = req.file.mimetype;
  const isVideo  = mimeType.startsWith('video/');
  try {
    const fileData = fs.readFileSync(filePath);
    const b64 = fileData.toString('base64');
    if (!isVideo && req.file.size < 5 * 1024 * 1024) {
      const uploadRes = await uploadBase64Media(account.accessToken, b64);
      fs.unlinkSync(filePath);
      return res.json({ mediaId: uploadRes.media_id_string });
    }
    const initOptions = { hostname:'upload.twitter.com', path:'/1.1/media/upload.json', method:'POST', headers:{'Authorization':`Bearer ${account.accessToken}`,'Content-Type':'application/x-www-form-urlencoded'} };
    const initBody = new URLSearchParams({ command:'INIT', total_bytes: req.file.size, media_type: mimeType, media_category: isVideo?'tweet_video':'tweet_image' }).toString();
    const initRes = await new Promise((resolve,reject) => {
      const req2=https.request({...initOptions,headers:{...initOptions.headers,'Content-Length':Buffer.byteLength(initBody)}},(r)=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{try{resolve(JSON.parse(d));}catch{reject(d);}});});
      req2.on('error',reject);req2.write(initBody);req2.end();
    });
    const mediaId = initRes.media_id_string;
    const chunkSize = 5*1024*1024;
    let seg=0;
    for(let offset=0;offset<fileData.length;offset+=chunkSize){
      const chunk=fileData.slice(offset,offset+chunkSize);
      const boundary='----XPB'+Date.now();
      const chunkBody=Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\n\r\nAPPEND\r\n--${boundary}\r\nContent-Disposition: form-data; name="media_id"\r\n\r\n${mediaId}\r\n--${boundary}\r\nContent-Disposition: form-data; name="segment_index"\r\n\r\n${seg++}\r\n--${boundary}\r\nContent-Disposition: form-data; name="media_data"\r\n\r\n`),Buffer.from(chunk.toString('base64')),Buffer.from(`\r\n--${boundary}--\r\n`)]);
      await new Promise((resolve,reject)=>{const req3=https.request({hostname:'upload.twitter.com',path:'/1.1/media/upload.json',method:'POST',headers:{'Authorization':`Bearer ${account.accessToken}`,'Content-Type':`multipart/form-data; boundary=${boundary}`,'Content-Length':chunkBody.length}},(r)=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>resolve(d));});req3.on('error',reject);req3.write(chunkBody);req3.end();});
    }
    const finalBody=new URLSearchParams({command:'FINALIZE',media_id:mediaId}).toString();
    await new Promise((resolve,reject)=>{const req4=https.request({hostname:'upload.twitter.com',path:'/1.1/media/upload.json',method:'POST',headers:{'Authorization':`Bearer ${account.accessToken}`,'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(finalBody)}},(r)=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>resolve(d));});req4.on('error',reject);req4.write(finalBody);req4.end();});
    fs.unlinkSync(filePath);
    if(isVideo) await waitForVideoProcessing(account.accessToken, mediaId);
    res.json({ mediaId });
  } catch(err) { try{fs.unlinkSync(filePath);}catch{} console.error(err); res.status(500).json({ error: err.message }); }
});

app.post('/post', async (req, res) => {
  const { accountIds, text, mediaIds } = req.body;
  if (!accountIds?.length) return res.status(400).json({ error: 'Selecione ao menos uma conta' });
  const results = [];
  for (const accountId of accountIds) {
    const account = accounts[accountId];
    if (!account) { results.push({ accountId, error: 'Conta nao encontrada' }); continue; }
    const payload = { text: text || ' ' };
    if (mediaIds?.length) payload.media = { media_ids: mediaIds };
    try {
      const tweetRes = await apiRequest('POST', 'https://api.twitter.com/2/tweets', account.accessToken, payload);
      if (tweetRes.data?.data?.id) results.push({ accountId, username: account.username, tweetId: tweetRes.data.data.id, ok: true });
      else results.push({ accountId, username: account.username, error: JSON.stringify(tweetRes.data), ok: false });
    } catch(err) { results.push({ accountId, username: account.username, error: err.message, ok: false }); }
  }
  res.json({ results });
});

app.post('/auth/refresh/:id', async (req, res) => {
  const account = accounts[req.params.id];
  if (!account?.refreshToken) return res.status(404).json({ error: 'Sem refresh token' });
  try {
    const data = await postForm('https://api.twitter.com/2/oauth2/token', { grant_type:'refresh_token', refresh_token: account.refreshToken, client_id: process.env.TWITTER_CLIENT_ID });
    if (data.access_token) { account.accessToken=data.access_token; account.refreshToken=data.refresh_token||account.refreshToken; res.json({ok:true}); }
    else res.status(400).json({ error: data });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`\n✅ XPanel rodando em http://localhost:${PORT}\n`));
