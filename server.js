require('dotenv').config();
const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const multer   = require('multer');
const cors     = require('cors');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const https    = require('https');
const Database = require('better-sqlite3');

const app = express();
const db = new Database(path.join(__dirname, 'xpanel.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS twitter_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, twitter_id TEXT NOT NULL, username TEXT NOT NULL, name TEXT NOT NULL, avatar TEXT, access_token TEXT NOT NULL, refresh_token TEXT, added_at TEXT DEFAULT (datetime('now')), UNIQUE(user_id, twitter_id));
  CREATE TABLE IF NOT EXISTS pkce_store (state TEXT PRIMARY KEY, verifier TEXT NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER DEFAULT (strftime('%s','now')));
`);

app.use(cors({origin:true,credentials:true}));
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,cookie:{secure:false,httpOnly:true,maxAge:7*24*60*60*1000}}));
app.use(express.static(path.join(__dirname,'public')));
const upload = multer({dest:'uploads/',limits:{fileSize:512*1024*1024}});

function requireAuth(req,res,next){if(!req.session.userId)return res.status(401).json({error:'Não autenticado'});next();}
function base64url(buf){return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');}
function generatePKCE(){const v=base64url(crypto.randomBytes(32));const c=base64url(crypto.createHash('sha256').update(v).digest());return{verifier:v,challenge:c};}

function apiRequest(method,url,token,body){
  return new Promise((resolve,reject)=>{
    const parsed=new URL(url);const headers={'Authorization':`Bearer ${token}`,'User-Agent':'XPanel/2.0'};
    let postData;
    if(body){postData=JSON.stringify(body);headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(postData);}
    const req=https.request({hostname:parsed.hostname,path:parsed.pathname+parsed.search,method,headers},(res)=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(d)});}catch{resolve({status:res.statusCode,data:d});}});});
    req.on('error',reject);if(postData)req.write(postData);req.end();
  });
}
function postForm(url,params){
  return new Promise((resolve,reject)=>{
    const body=new URLSearchParams(params).toString();
    const headers={'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body),'Authorization':`Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`};
    const parsed=new URL(url);
    const req=https.request({hostname:parsed.hostname,path:parsed.pathname,method:'POST',headers},(res)=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(JSON.parse(d));}catch{resolve(d);}});});
    req.on('error',reject);req.write(body);req.end();
  });
}

app.post('/api/register',async(req,res)=>{
  const{email,password,name}=req.body;
  if(!email||!password||!name)return res.status(400).json({error:'Preencha todos os campos'});
  if(password.length<6)return res.status(400).json({error:'Senha deve ter ao menos 6 caracteres'});
  try{const hash=bcrypt.hashSync(password,10);const stmt=db.prepare('INSERT INTO users (email,password,name) VALUES (?,?,?)');const result=stmt.run(email.toLowerCase().trim(),hash,name.trim());req.session.userId=result.lastInsertRowid;req.session.userName=name.trim();res.json({ok:true,name:name.trim()});}
  catch(e){if(e.message.includes('UNIQUE'))return res.status(409).json({error:'E-mail já cadastrado'});res.status(500).json({error:e.message});}
});

app.post('/api/login',(req,res)=>{
  const{email,password}=req.body;
  if(!email||!password)return res.status(400).json({error:'Preencha todos os campos'});
  const user=db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase().trim());
  if(!user||!bcrypt.compareSync(password,user.password))return res.status(401).json({error:'E-mail ou senha incorretos'});
  req.session.userId=user.id;req.session.userName=user.name;res.json({ok:true,name:user.name});
});

app.post('/api/logout',(req,res)=>{req.session.destroy();res.json({ok:true});});
app.get('/api/me',(req,res)=>{if(!req.session.userId)return res.json({loggedIn:false});res.json({loggedIn:true,name:req.session.userName,userId:req.session.userId});});

app.get('/auth/start',requireAuth,(req,res)=>{
  if(!process.env.TWITTER_CLIENT_ID)return res.status(500).json({error:'TWITTER_CLIENT_ID não configurado'});
  const state=base64url(crypto.randomBytes(16));const pkce=generatePKCE();
  db.prepare("DELETE FROM pkce_store WHERE user_id=? OR created_at<strftime('%s','now')-600").run(req.session.userId);
  db.prepare('INSERT INTO pkce_store (state,verifier,user_id) VALUES (?,?,?)').run(state,pkce.verifier,req.session.userId);
  const params=new URLSearchParams({response_type:'code',client_id:process.env.TWITTER_CLIENT_ID,redirect_uri:process.env.CALLBACK_URL||'http://localhost:3000/auth/callback',scope:'tweet.read tweet.write users.read offline.access',state,code_challenge:pkce.challenge,code_challenge_method:'S256'});
  res.json({url:`https://twitter.com/i/oauth2/authorize?${params}`});
});

app.get('/auth/callback',async(req,res)=>{
  const{code,state,error}=req.query;
  if(error)return res.send(closePopup('',error));
  const row=db.prepare('SELECT * FROM pkce_store WHERE state=?').get(state);
  if(!row)return res.send(closePopup('','invalid_state'));
  db.prepare('DELETE FROM pkce_store WHERE state=?').run(state);
  try{
    const tokenData=await postForm('https://api.twitter.com/2/oauth2/token',{grant_type:'authorization_code',code,redirect_uri:process.env.CALLBACK_URL||'http://localhost:3000/auth/callback',client_id:process.env.TWITTER_CLIENT_ID,code_verifier:row.verifier});
    if(!tokenData.access_token)return res.send(closePopup('',JSON.stringify(tokenData)));
    const userRes=await apiRequest('GET','https://api.twitter.com/2/users/me?user.fields=profile_image_url,name,username',tokenData.access_token);
    const tu=userRes.data.data;if(!tu)return res.send(closePopup('','user_fetch_failed'));
    db.prepare('INSERT INTO twitter_accounts (user_id,twitter_id,username,name,avatar,access_token,refresh_token) VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id,twitter_id) DO UPDATE SET access_token=excluded.access_token,refresh_token=excluded.refresh_token,avatar=excluded.avatar,name=excluded.name').run(row.user_id,tu.id,tu.username,tu.name,tu.profile_image_url?.replace('_normal','_bigger')||'',tokenData.access_token,tokenData.refresh_token||'');
    res.send(closePopup(tu.username,''));
  }catch(err){console.error(err);res.send(closePopup('',err.message));}
});

function closePopup(username,error){return `<!DOCTYPE html><html><body><script>if(window.opener){window.opener.postMessage({type:'xpanel-auth',username:${JSON.stringify(username)},error:${JSON.stringify(error)}},'*');}window.close();<\/script><p>Conectado!</p></body></html>`;}

app.get('/api/accounts',requireAuth,(req,res)=>{res.json(db.prepare('SELECT id,twitter_id,username,name,avatar,added_at FROM twitter_accounts WHERE user_id=? ORDER BY added_at').all(req.session.userId));});
app.delete('/api/accounts/:id',requireAuth,(req,res)=>{db.prepare('DELETE FROM twitter_accounts WHERE id=? AND user_id=?').run(req.params.id,req.session.userId);res.json({ok:true});});

function v1Req(token,body){return new Promise((resolve,reject)=>{const opts={hostname:'upload.twitter.com',path:'/1.1/media/upload.json',method:'POST',headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}};const req=https.request(opts,r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{try{resolve(JSON.parse(d));}catch{reject(d);}});});req.on('error',reject);req.write(body);req.end();});}

app.post('/api/upload-media',requireAuth,upload.single('media'),async(req,res)=>{
  const acct=db.prepare('SELECT * FROM twitter_accounts WHERE id=? AND user_id=?').get(req.body.accountId,req.session.userId);
  if(!acct)return res.status(401).json({error:'Conta não encontrada'});
  const filePath=req.file.path;const mimeType=req.file.mimetype;const isVideo=mimeType.startsWith('video/');
  try{
    const fileData=fs.readFileSync(filePath);const b64=fileData.toString('base64');
    if(!isVideo&&req.file.size<5*1024*1024){const r=await v1Req(acct.access_token,new URLSearchParams({media_data:b64}).toString());fs.unlinkSync(filePath);return res.json({mediaId:r.media_id_string});}
    const initRes=await v1Req(acct.access_token,new URLSearchParams({command:'INIT',total_bytes:req.file.size,media_type:mimeType,media_category:isVideo?'tweet_video':'tweet_image'}).toString());
    const mediaId=initRes.media_id_string;const chunkSize=5*1024*1024;let seg=0;
    for(let o=0;o<fileData.length;o+=chunkSize){const chunk=fileData.slice(o,o+chunkSize);const boundary='----XPB'+Date.now();const cb=Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\n\r\nAPPEND\r\n--${boundary}\r\nContent-Disposition: form-data; name="media_id"\r\n\r\n${mediaId}\r\n--${boundary}\r\nContent-Disposition: form-data; name="segment_index"\r\n\r\n${seg++}\r\n--${boundary}\r\nContent-Disposition: form-data; name="media_data"\r\n\r\n`),Buffer.from(chunk.toString('base64')),Buffer.from(`\r\n--${boundary}--\r\n`)]);await new Promise((res2,rej)=>{const r2=https.request({hostname:'upload.twitter.com',path:'/1.1/media/upload.json',method:'POST',headers:{'Authorization':`Bearer ${acct.access_token}`,'Content-Type':`multipart/form-data; boundary=${boundary}`,'Content-Length':cb.length}},(r)=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>res2(d));});r2.on('error',rej);r2.write(cb);r2.end();});}
    await v1Req(acct.access_token,new URLSearchParams({command:'FINALIZE',media_id:mediaId}).toString());
    fs.unlinkSync(filePath);
    if(isVideo){await new Promise((res3,rej)=>{const chk=()=>{const r3=https.request({hostname:'upload.twitter.com',path:`/1.1/media/upload.json?command=STATUS&media_id=${mediaId}`,method:'GET',headers:{'Authorization':`Bearer ${acct.access_token}`}},(r)=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{try{const j=JSON.parse(d);const s=j.processing_info?.state;if(s==='succeeded')return res3();if(s==='failed')return rej(new Error('failed'));setTimeout(chk,(j.processing_info?.check_after_secs||5)*1000);}catch{res3();}});});r3.on('error',rej);r3.end();};chk();});}
    res.json({mediaId});
  }catch(err){try{fs.unlinkSync(filePath);}catch{}res.status(500).json({error:err.message});}
});

app.post('/api/post',requireAuth,async(req,res)=>{
  const{accountIds,text,mediaIds}=req.body;
  if(!accountIds?.length)return res.status(400).json({error:'Selecione ao menos uma conta'});
  const results=[];
  for(const accountId of accountIds){
    const acct=db.prepare('SELECT * FROM twitter_accounts WHERE id=? AND user_id=?').get(accountId,req.session.userId);
    if(!acct){results.push({accountId,error:'Conta não encontrada',ok:false});continue;}
    const payload={text:text||' '};if(mediaIds?.length)payload.media={media_ids:mediaIds};
    try{
      const r=await apiRequest('POST','https://api.twitter.com/2/tweets',acct.access_token,payload);
      if(r.data?.data?.id){results.push({accountId,username:acct.username,tweetId:r.data.data.id,ok:true});}
      else{results.push({accountId,username:acct.username,error:JSON.stringify(r.data),ok:false});}
    }catch(err){results.push({accountId,username:acct.username,error:err.message,ok:false});}
  }
  res.json({results});
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`\n✅ XPanel v2 em http://localhost:${PORT}\n`));