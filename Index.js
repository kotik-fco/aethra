'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const OPS=require('../../shared/ops.js'),R=require('./rules.js'),DBM=require('./db.js');
const cfg={port:+process.env.PORT||8080,dataDir:process.env.DATA_DIR||path.join(__dirname,'../data'),dbUrl:process.env.DATABASE_URL||'',
 origins:(process.env.ORIGIN||'').split(',').map(s=>s.trim()).filter(Boolean),trustProxy:process.env.TRUST_PROXY==='1',
 devSalt:process.env.DEV_SALT||'',devHash:process.env.DEV_HASH||'',devIter:+process.env.DEV_ITER||210000,
 web:path.resolve(process.env.WEB_DIR||path.join(__dirname,'../../web')),serveWeb:process.env.SERVE_WEB!=='0'};
const BAD=new Set(['__proto__','constructor','prototype']),OPK=['set','del','add','rm','ord','sadd','srm'];
const RESERVED=/^(admin|administrator|root|system|aethra|support|moderator|mod|developer|dev|staff|owner|everyone|here|null|undefined)$/i;
const POS0={p_dev:{name:'Developer',badge:'👨‍💻',color:'#7c5cff',rank:4},p_adm:{name:'Admin',badge:'🛡️',color:'#ef4466',rank:3},p_mod:{name:'Moderator',badge:'🔨',color:'#34d399',rank:2},p_sup:{name:'Support',badge:'🎧',color:'#22d3ee',rank:1}};
const COL=['#7c5cff','#22d3ee','#f472b6','#34d399','#fbbf24','#fb7185','#60a5fa'];
let db,S={users:{},srv:{},dm:{},inv:{},plat:null,up:{}};const dirty=new Set(),conns=new Set(),pres={},sessions=new Map();

/* ---------- helpers ---------- */
const now=()=>Date.now(),rid=n=>crypto.randomBytes(n).toString('hex'),sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const hits=new Map();function rate(k,max,ms){const t=now(),a=(hits.get(k)||[]).filter(x=>t-x<ms);if(a.length>=max){hits.set(k,a);return false}a.push(t);hits.set(k,a);return true}
setInterval(()=>{const t=now();for(const[k,a]of hits){const f=a.filter(x=>t-x<3600000);f.length?hits.set(k,f):hits.delete(k)}db&&db.purgeSessions().catch(()=>{})},60000).unref();
const ipOf=req=>cfg.trustProxy?String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress:req.socket.remoteAddress;
class HttpErr extends Error{constructor(s,m){super(m);this.s=s}}
function cors(req,res){const o=req.headers.origin;if(o&&(!cfg.origins.length||cfg.origins.includes(o)||cfg.origins.includes('*'))){res.setHeader('Access-Control-Allow-Origin',cfg.origins.includes('*')?'*':o);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization,X-Client');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');res.setHeader('Access-Control-Max-Age','600')}}
function secHeaders(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','microphone=(self), camera=(), geolocation=()');res.setHeader('Cross-Origin-Resource-Policy','cross-origin')}
const send=(res,s,o)=>{const b=JSON.stringify(o);res.writeHead(s,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(b)};
function body(req,max=1.6e6){return new Promise((ok,no)=>{let n=0;const ch=[];req.on('data',c=>{n+=c.length;if(n>max){no(new HttpErr(413,'e_big'));req.destroy()}else ch.push(c)});req.on('end',()=>{try{ok(ch.length?JSON.parse(Buffer.concat(ch).toString('utf8')):{})}catch(e){no(new HttpErr(400,'e_json'))}});req.on('error',no)})}
const scrypt=(pw,salt)=>new Promise((ok,no)=>crypto.scrypt(pw,salt,64,{N:16384,r:8,p:1,maxmem:64*1024*1024},(e,k)=>e?no(e):ok(k)));
async function hashPw(pw){const s=crypto.randomBytes(16);return'scrypt$'+s.toString('hex')+'$'+(await scrypt(pw,s)).toString('hex')}
async function checkPw(pw,st){const[,s,h]=String(st).split('$');if(!s||!h)return false;const k=await scrypt(pw,Buffer.from(s,'hex')),b=Buffer.from(h,'hex');return k.length===b.length&&crypto.timingSafeEqual(k,b)}
let DUMMY;const save=(c,id)=>dirty.add(c+'\u0000'+id);
async function flush(){const l=[...dirty];dirty.clear();for(const k of l){const[c,id]=k.split('\u0000');const d=c==='plat'?S.plat:S[c][id];try{if(d===undefined)await db.delDoc(c,id);else await db.putDoc(c,id,d)}catch(e){console.error('persist',e.message);dirty.add(k)}}}
const rank=uid=>R.rankOf(S,S.users[uid]);
const banned=uid=>{const b=S.plat.bans[uid];return b&&(!b.until||b.until>now())};

/* ---------- views (what a client may see) ---------- */
const PUB=['id','name','color','banner','banner2','bio','pron','status','custom','ts','img','bimg','pos','aurum','noAurum','gb','early','fr','tagFrom','nstyle','pv'];
const PUBF=new Set(PUB);
function pubUser(u,viewer){const o={};for(const k of PUB)if(u[k]!==undefined)o[k]=u[k];
 Object.assign(o,{inc:(u.inc||[]).includes(viewer)?[viewer]:[],out:(u.out||[]).includes(viewer)?[viewer]:[],bl:(u.bl||[]).includes(viewer)?[viewer]:[],ig:[],notes:{},read:{},mread:{},nf:{},ui:{},vs:{},lang:'ru',theme:'dark',accent:'#7c5cff',dev:false,test:false,rl:false});return o}
function stateFor(uid){const users={};for(const[id,u]of Object.entries(S.users))users[id]=id===uid?u:pubUser(u,uid);
 const srv={},inv={},dm={},r=rank(uid);for(const[id,g]of Object.entries(S.srv))if(g.mem[uid]){srv[id]=g;for(const c of Object.keys(g.invites||{}))inv[c]=id;if(g.vanity)inv[g.vanity]=id}
 for(const[k,l]of Object.entries(S.dm))if(k.split('_').includes(uid))dm[k]=l;
 const P=S.plat,plat={pos:P.pos,badges:P.badges,ann:P.ann,tickets:r>=1?P.tickets:P.tickets.filter(t=>t.uid===uid),bans:r>=2?P.bans:(P.bans[uid]?{[uid]:P.bans[uid]}:{})};
 return{uid,users,srv,dm,inv,plat}}

/* ---------- op pipeline ---------- */
function validOp(op){if(!op||typeof op!=='object'||!['users','srv','dm','inv','plat'].includes(op.c)||typeof op.id!=='string'||!OPK.includes(op.o)||!Array.isArray(op.p)||op.p.length>10)return false;
 if(op.c==='plat'?op.id!=='':!/^[A-Za-z0-9_-]{1,100}$/.test(op.id))return false;
 if(!op.p.every(s=>typeof s==='string'&&s.length<=64&&!BAD.has(s)))return false;
 if((op.o==='add'||op.o==='set'||op.o==='sadd'||op.o==='srm')&&R.dirty(op.v))return false;
 if(op.o==='add'&&!(op.v&&typeof op.v.id==='string'&&R.ID.test(op.v.id)))return false;
 if(op.o==='rm'&&typeof op.id!=='string')return false;if(op.o==='ord'&&!(Array.isArray(op.ids)&&op.ids.length<=600&&op.ids.every(x=>typeof x==='string')))return false;
 if(op.o==='add'&&op.at!==-1&&!(Number.isInteger(op.at)&&op.at>=0&&op.at<5000))return false;return true}
function makeCtx(uid){const W=new Map(),key=(c,id)=>c+'/'+id;
 const ctx={uid,now:now(),S,rank:rank(uid),W,
  get(c,id){const k=key(c,id);if(W.has(k))return W.get(k)||undefined;const d=c==='plat'?S.plat:S[c][id];if(d===undefined)return undefined;const cl=structuredClone(d);W.set(k,cl);return cl},
  orig:(c,id)=>c==='plat'?S.plat:S[c][id],set:(c,id,d)=>W.set(key(c,id),d),del:(c,id)=>W.set(key(c,id),null),
  upload:id=>S.up[id],rate,nameFree:(n,me)=>!Object.values(S.users).some(u=>u.id!==me&&u.name.toLowerCase()===n.toLowerCase())&&!RESERVED.test(n.trim())};
 return ctx}
function applyTo(ctx,op){const{c,id}=op;
 if(c==='plat'){ctx.set('plat','',OPS.applyOp(ctx.get('plat',''),op));return}
 if(!op.p.length){if(op.o==='del')ctx.del(c,id);else ctx.set(c,id,op.v);return}
 const d=ctx.get(c,id);if(d===undefined)throw new Error('missing doc');ctx.set(c,id,OPS.applyOp(d,op))}
function audience(op,pre,actor){const all='*';
 if(op.c==='users'){if(!op.p.length)return op.o==='set'?[new Set([op.id]),{...op,v:pubUser(op.v,'')}]:[all,null];
  const f=op.p[0];if(PUBF.has(f))return[all,null];if(['inc','out','bl'].includes(f)){const s=new Set([op.id,actor]);if(typeof op.v==='string')s.add(op.v);return[s,null]}return[new Set([op.id]),null]}
 if(op.c==='srv'){const s=new Set([actor,...(pre.srv[op.id]||[]),...Object.keys((S.srv[op.id]||{}).mem||{})]);return[s,null]}
 if(op.c==='dm')return[new Set(op.id.split('_')),null];
 if(op.c==='inv'){const sid=op.p.length?null:(op.v||pre.inv[op.id]);const g=S.srv[sid];return[new Set([actor,...(g?Object.keys(g.mem):[])]),null]}
 if(op.c==='plat'){const f=op.p[0];if(f==='tickets'){const t=op.p.length===1?op.v:S.plat.tickets.find(x=>x.id===(op.p[1]||'').slice(1));return[new Set([actor,t&&t.uid,...Object.keys(S.users).filter(u=>rank(u)>=1)]),null]}
  if(f==='bans')return[new Set([op.p[1],...Object.keys(S.users).filter(u=>rank(u)>=2)]),null];return[all,null]}
 return[new Set(),null]}
function deliver(ops,pre,actor,sid){const per=new Map(),add=(u,op)=>{if(!per.has(u))per.set(u,[]);per.get(u).push(op)};
 for(const op of ops){const[full,pubOp]=audience(op,pre,actor);
  for(const cn of conns){if(full==='*'||full.has(cn.uid))add(cn.uid,op);else if(pubOp)add(cn.uid,pubOp)}}
 for(const cn of conns){if(cn.sid&&cn.sid===sid)continue;const l=per.get(cn.uid);if(l&&l.length)ev(cn,'ops',l)}}
const ev=(cn,name,d)=>{try{cn.res.write('event: '+name+'\ndata: '+JSON.stringify(d)+'\n\n')}catch(e){}};
const broadcast=(name,d)=>conns.forEach(c=>ev(c,name,d));
async function commit(uid,ops,sid){
 if(!Array.isArray(ops)||!ops.length||ops.length>300)throw new HttpErr(400,'bad batch');
 const ctx=makeCtx(uid),pre={srv:{},inv:{}},applied=[];
 for(const op of ops){
  if(!validOp(op))throw new HttpErr(400,'invalid op');
  if(op.c==='srv'&&!(op.id in pre.srv))pre.srv[op.id]=Object.keys((S.srv[op.id]||{}).mem||{});if(op.c==='inv')pre.inv[op.id]=S.inv[op.id];
  const why=R.authorize(ctx,op);if(why){db.log(uid,'op_denied',op.c+'/'+op.id,{why,p:op.p,o:op.o});throw new HttpErr(403,why)}
  try{applyTo(ctx,op)}catch(e){throw new HttpErr(409,'conflict: '+e.message)}applied.push(op)}
 for(const[k,d]of ctx.W){const i=k.indexOf('/'),c=k.slice(0,i),id=k.slice(i+1);
  if(d===null){if(c==='plat')continue;delete S[c][id];if(c==='srv')for(const[code,sid2]of Object.entries(S.inv))if(sid2===id){delete S.inv[code];save('inv',code)}}
  else if(c==='plat')S.plat=d;else S[c][id]=d;save(c,id)}
 for(const op of applied)if(op.c==='users'&&!op.p.length&&op.o==='del'){}
 deliver(applied,pre,uid,sid);return applied.length}
function internalOps(ops,actor){const ctx=makeCtx(actor),pre={srv:{},inv:{}};for(const op of ops){if(op.c==='srv'&&!(op.id in pre.srv))pre.srv[op.id]=Object.keys((S.srv[op.id]||{}).mem||{});applyTo(ctx,op)}
 for(const[k,d]of ctx.W){const i=k.indexOf('/'),c=k.slice(0,i),id=k.slice(i+1);if(d===null){delete S[c][id]}else if(c==='plat')S.plat=d;else S[c][id]=d;save(c,id)}deliver(ops,pre,actor,null)}

/* ---------- accounts ---------- */
async function newSession(uid,req){const tok=crypto.randomBytes(32).toString('base64url'),th=sha(tok),exp=now()+30*864e5;await db.putSession(th,uid,exp,ipOf(req),req.headers['user-agent']);sessions.set(th,{uid,expires:exp});return tok}
async function authed(req){const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))throw new HttpErr(401,'e_auth');const th=sha(h.slice(7).trim());
 let s=sessions.get(th);if(!s){s=await db.getSession(th);if(s)sessions.set(th,s)}if(!s||s.expires<now()||!S.users[s.uid]){sessions.delete(th);throw new HttpErr(401,'e_auth')}
 if(banned(s.uid))throw new HttpErr(403,'e_banned');return{uid:s.uid,th}}
function userDoc(id,name){const c=()=>COL[crypto.randomInt(7)],a=c();return{id,name,color:a,banner:a,banner2:c(),bio:'',pron:'',status:'online',custom:'',ts:now(),fr:[],inc:[],out:[],bl:[],ig:[],notes:{},read:{},lang:'ru',theme:'dark',accent:'#7c5cff',dev:false,test:false,rl:false,early:Object.keys(S.users).length<10,nf:{sound:1,desk:0,dm:1,ping:1,every:1},mread:{},pv:{fr:1,dm:1},ui:{fs:15,cp:0,rm:0},gb:[],vs:{}}}
async function purgeUser(uid){
 for(const g of Object.values(S.srv)){if(g.owner===uid){const o=Object.keys(g.mem).find(x=>x!==uid);if(o){g.owner=o;g.mem[o].roles=[g.roles[0].id];delete g.mem[uid];delete(g.pulses||{})[uid];save('srv',g.id)}else{delete S.srv[g.id];save('srv',g.id);for(const[c,s]of Object.entries(S.inv))if(s===g.id){delete S.inv[c];save('inv',c)}}}
  else if(g.mem[uid]){delete g.mem[uid];delete(g.pulses||{})[uid];save('srv',g.id)}}
 for(const k of Object.keys(S.dm))if(k.split('_').includes(uid)){delete S.dm[k];save('dm',k)}
 for(const u of Object.values(S.users)){if(u.id===uid)continue;let ch=false;for(const f of['fr','inc','out','bl','ig'])if((u[f]||[]).includes(uid)){u[f]=u[f].filter(x=>x!==uid);ch=true}if(u.notes&&u.notes[uid]){delete u.notes[uid];ch=true}if(ch)save('users',u.id)}
 delete S.users[uid];save('users',uid);delete S.plat.bans[uid];save('plat','');
 for(const[id,m]of Object.entries(S.up))if(m.uid===uid)delete S.up[id];
 await db.delAuth(uid);await db.delSessionsOf(uid);await db.delUploadsOf(uid);for(const[th,s]of sessions)if(s.uid===uid)sessions.delete(th);
 for(const cn of[...conns])if(cn.uid===uid){ev(cn,'kick',{});try{cn.res.end()}catch(e){}conns.delete(cn)}broadcast('resync',{})}

/* ---------- uploads ---------- */
function sniff(b){if(b.length<12)return null;
 if(b[0]===0x89&&b[1]===0x50&&b[2]===0x4e&&b[3]===0x47)return{mime:'image/png',ext:'png',anim:b.includes(Buffer.from('acTL'))};
 if(b[0]===0xff&&b[1]===0xd8&&b[2]===0xff)return{mime:'image/jpeg',ext:'jpg',anim:false};
 if(b.slice(0,3).toString()==='GIF')return{mime:'image/gif',ext:'gif',anim:true};
 if(b.slice(0,4).toString()==='RIFF'&&b.slice(8,12).toString()==='WEBP')return{mime:'image/webp',ext:'webp',anim:b.slice(12,16).toString()==='VP8X'&&!!(b[20]&2)};return null}
async function upload(uid,j){const m=/^data:([\w\/+.-]+);base64,([A-Za-z0-9+\/=]+)$/.exec(String(j.data||''));if(!m)throw new HttpErr(400,'e_bad_file');
 const buf=Buffer.from(m[2],'base64');if(buf.length>3.2e6)throw new HttpErr(413,'e_big');
 const st=await db.uploadStats(uid);if(st.count>=300||st.bytes+buf.length>80e6)throw new HttpErr(429,'e_quota');
 let info=sniff(buf);if(!info){if(j.kind!=='file'||buf.length>4e5)throw new HttpErr(415,'e_bad_file');info={mime:'application/octet-stream',ext:'bin',anim:false}}
 const u=S.users[uid];if(info.anim&&!(R.aur(u,now())||rank(uid)>=3))throw new HttpErr(403,'e_anim');
 if(!rate('up:'+uid,30,60000))throw new HttpErr(429,'e_rate');
 const id=rid(12);await db.putUpload(id,uid,info.mime,info.anim,String(j.kind||'').slice(0,12),buf);S.up[id]={uid,anim:info.anim};return{url:'/uploads/'+id+'.'+info.ext,anim:info.anim}}

/* ---------- routes ---------- */
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css','.json':'application/json','.png':'image/png','.svg':'image/svg+xml','.ico':'image/x-icon','.txt':'text/plain'};
async function route(req,res,url){const m=req.method,p=url.pathname;
 if(p==='/api/health')return send(res,200,{ok:true,driver:db.driver,users:Object.keys(S.users).length});
 if(p==='/api/register'&&m==='POST'){const ip=ipOf(req);if(!rate('reg:'+ip,5,3600000))throw new HttpErr(429,'e_rate');const j=await body(req,5000);
  const name=String(j.name||'').trim().replace(/\s+/g,' '),pw=String(j.password||'');
  if(!/^[\p{L}\p{N}_. -]{3,20}$/u.test(name)||pw.length<8||pw.length>128)throw new HttpErr(400,'e_short');
  if(RESERVED.test(name)||await db.authByName(name.toLowerCase())||Object.values(S.users).some(u=>u.name.toLowerCase()===name.toLowerCase()))throw new HttpErr(409,'e_exists');
  const uid='u'+rid(8),doc=userDoc(uid,name);await db.createAuth(uid,name,await hashPw(pw));S.users[uid]=doc;save('users',uid);
  deliver([{c:'users',id:uid,p:[],o:'set',v:doc}],{srv:{},inv:{}},uid,null);db.log(uid,'register','',{ip});return send(res,200,{token:await newSession(uid,req)})}
 if(p==='/api/login'&&m==='POST'){const ip=ipOf(req),j=await body(req,5000),nm=String(j.name||'').trim().toLowerCase();
  if(!rate('login:'+ip,20,600000)||!rate('loginu:'+nm,8,600000))throw new HttpErr(429,'e_rate');
  const a=await db.authByName(nm);DUMMY=DUMMY||await hashPw('x');const ok=await checkPw(String(j.password||''),a?a.pass:DUMMY);
  if(!a||!ok){db.log('', 'login_fail',nm,{ip});throw new HttpErr(401,'e_cred')}if(banned(a.uid))throw new HttpErr(403,'e_banned');return send(res,200,{token:await newSession(a.uid,req)})}
 if(p==='/api/invite-info'&&m==='GET'){if(!rate('inv:'+ipOf(req),60,60000))throw new HttpErr(429,'e_rate');const sid=S.inv[(url.searchParams.get('code')||'').toLowerCase()],g=S.srv[sid];if(!g)throw new HttpErr(404,'e_inv');
  return send(res,200,{name:g.name,icon:g.icon||null,ibg:g.ibg||null,members:Object.keys(g.mem).length,lvl:R.lvl(g,S,now()),tag:g.tag||null})}
 if(p.startsWith('/uploads/')&&m==='GET'){const mm=/^\/uploads\/([a-f0-9]{24})\.\w{2,5}$/.exec(p);if(!mm)throw new HttpErr(404,'nf');const u=await db.getUpload(mm[1]);if(!u)throw new HttpErr(404,'nf');
  const h={'Content-Type':u.mime,'Cache-Control':'public, max-age=31536000, immutable','Content-Length':u.bytes.length};if(u.mime==='application/octet-stream')h['Content-Disposition']='attachment';res.writeHead(200,h);return res.end(u.bytes)}
 if(p.startsWith('/api/')){
  const au=await authed(req),uid=au.uid,sid=String(req.headers['x-client']||'').slice(0,40);
  if(p==='/api/state'&&m==='GET')return send(res,200,stateFor(uid));
  if(p==='/api/stream'&&m==='GET'){res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-store','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write('retry: 2000\n\n');
   const cn={uid,sid,res};conns.add(cn);pres[uid]={t:now(),a:now()};ev(cn,'hello',{uid});sendPres();const ka=setInterval(()=>{try{res.write(': ka\n\n')}catch(e){}},20000);
   req.on('close',()=>{clearInterval(ka);conns.delete(cn);pres[uid]={...pres[uid],t:now()};sendPres()});return}
  if(p==='/api/ops'&&m==='POST'){if(!rate('ops:'+uid,120,60000))throw new HttpErr(429,'e_rate');const j=await body(req);return send(res,200,{ok:true,n:await commit(uid,j.ops,sid)})}
  if(p==='/api/hb'&&m==='POST'){const j=await body(req,200);pres[uid]={t:now(),a:now()-Math.max(0,Math.min(+j.a||0,36e5))};return send(res,200,{ok:true})}
  if(p==='/api/logout'&&m==='POST'){await db.delSession(au.th);sessions.delete(au.th);return send(res,200,{ok:true})}
  if(p==='/api/upload'&&m==='POST'){const j=await body(req,4.6e6);return send(res,200,await upload(uid,j))}
  if(p==='/api/join'&&m==='POST'){if(!rate('join:'+uid,20,600000))throw new HttpErr(429,'e_rate');const j=await body(req,500),code=String(j.code||'').trim().split('/').pop().toLowerCase(),g=S.srv[S.inv[code]];
   if(!g)throw new HttpErr(404,'e_inv');if(g.bans.includes(uid))throw new HttpErr(403,'e_ban');if(Object.keys(g.mem).length>=5000)throw new HttpErr(409,'full');
   if(!g.mem[uid]){const ops=[{c:'srv',id:g.id,p:['mem',uid],o:'set',v:{roles:[g.roles[g.roles.length-1].id],nick:'',to:0,joined:now()}}];if(g.invites[code])ops.push({c:'srv',id:g.id,p:['invites',code,'uses'],o:'set',v:g.invites[code].uses+1});internalOps(ops,uid)}
   const g2=S.srv[g.id],inv={};for(const c of Object.keys(g2.invites||{}))inv[c]=g2.id;if(g2.vanity)inv[g2.vanity]=g2.id;return send(res,200,{sid:g2.id,srv:g2,inv})}
  if(p==='/api/dev-unlock'&&m==='POST'){if(!cfg.devHash)throw new HttpErr(404,'nf');const ip=ipOf(req);
   if(!rate('dev:'+uid,5,3600000)||!rate('devip:'+ip,15,3600000))throw new HttpErr(429,'e_rate');const j=await body(req,300),code=String(j.code||'').trim().slice(0,100);
   const k=await new Promise((ok,no)=>crypto.pbkdf2(code,cfg.devSalt,cfg.devIter,32,'sha256',(e,d)=>e?no(e):ok(d))),want=Buffer.from(cfg.devHash,'hex');
   if(k.length!==want.length||!crypto.timingSafeEqual(k,want)){db.log(uid,'dev_unlock_fail','',{ip});throw new HttpErr(403,'badcode')}
   db.log(uid,'dev_unlock_ok','',{ip});internalOps([{c:'users',id:uid,p:['pos'],o:'set',v:'p_dev'}],uid);return send(res,200,{ok:true})}
  if(p==='/api/delete-account'&&m==='POST'){const j=await body(req,500),a=await db.authByUid(uid);if(!a||!(await checkPw(String(j.password||''),a.pass)))throw new HttpErr(403,'e_cred');db.log(uid,'delete_account','',{});await purgeUser(uid);return send(res,200,{ok:true})}
  if(p==='/api/admin/delete-user'&&m==='POST'){const j=await body(req,300),t=String(j.uid||'');if(rank(uid)<3||!S.users[t]||t===uid||rank(t)>=rank(uid))throw new HttpErr(403,'denied');db.log(uid,'admin_delete_user',t,{});await purgeUser(t);return send(res,200,{ok:true})}
  if(p==='/api/signal'&&m==='POST'){if(!rate('sig:'+uid,900,60000))throw new HttpErr(429,'e_rate');const j=await body(req,25000);let to=null;
   const inScope=room=>{const x=String(room||'').split(':');if(x[0]==='v'||x[0]==='c'){const g=S.srv[x[1]];return g&&g.mem[uid]?Object.keys(g.mem):null}if(x[0]==='d'&&x[1]){const pr=String(x[1]).split('_');return pr.includes(uid)?pr:null}return null};
   if(j.k==='typ'){const r=String(j.r||''),sc=r[0]==='d'?inScope(r):inScope('c:'+(j.s||'')+':'+r);if(sc)for(const cn of conns)if(sc.includes(cn.uid)&&cn.uid!==uid)ev(cn,'sig',{k:'typ',r,u:uid});return send(res,200,{ok:true})}
   if(j.k==='rtc'&&j.m&&['hello','bye','offer','answer','ice','state','ring'].includes(j.m.t)){const sc=j.m.t==='ring'?(inScope(j.m.room)||[]).filter(x=>x===j.m.to):inScope(j.m.room);
    if(sc)for(const cn of conns)if(sc.includes(cn.uid)&&!(cn.uid===uid&&cn.sid===sid))ev(cn,'sig',{k:'rtc',u:uid,m:{...j.m,uid}});return send(res,200,{ok:true})}throw new HttpErr(400,'bad signal')}
  throw new HttpErr(404,'nf')}
 /* static web (optional) */
 if(cfg.serveWeb&&(m==='GET'||m==='HEAD')){if(p==='/config.js'&&!fs.existsSync(path.join(cfg.web,'config.js'))||p==='/config.js'&&process.env.FORCE_SAME_ORIGIN==='1'){res.writeHead(200,{'Content-Type':MIME['.js'],'Cache-Control':'no-store'});return res.end('window.AETHRA_API=location.origin;')}
  let f=path.normalize(path.join(cfg.web,decodeURIComponent(p==='/'?'/index.html':p)));if(!f.startsWith(cfg.web)||!fs.existsSync(f)||fs.statSync(f).isDirectory())f=path.join(cfg.web,'index.html');
  const ext=path.extname(f);const h={'Content-Type':MIME[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'};
  if(ext==='.html'){h['X-Frame-Options']='DENY';h['Content-Security-Policy']="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}
  res.writeHead(200,h);return res.end(fs.readFileSync(f))}
 throw new HttpErr(404,'nf')}
function sendPres(){const o={},t=now(),on=new Set([...conns].map(c=>c.uid));for(const[u,x]of Object.entries(pres)){if(!S.users[u])continue;const age=on.has(u)?0:t-x.t;if(age<20000)o[u]=[age,Math.max(0,t-x.a)]}broadcast('pres',o)}

async function main(){
 db=await DBM.open(cfg);for(const d of await db.loadDocs()){if(d.c==='plat')S.plat=d.data;else S[d.c][d.id]=d.data}
 for(const u of await db.uploadMeta())S.up[u.id]={uid:u.uid,anim:u.anim};
 S.plat=S.plat||{pos:{},badges:{},tickets:[],bans:{},ann:''};for(const[k,v]of Object.entries(POS0))if(!S.plat.pos[k])S.plat.pos[k]={id:k,sys:1,...v};save('plat','');
 const srv=http.createServer(async(req,res)=>{secHeaders(res);cors(req,res);if(req.method==='OPTIONS'){res.writeHead(204);return res.end()}
  try{await route(req,res,new URL(req.url,'http://x'))}catch(e){if(e instanceof HttpErr){if(!res.headersSent)send(res,e.s,{error:e.message})}else{console.error(e);if(!res.headersSent)send(res,500,{error:'e_server'})}}});
 srv.requestTimeout=30000;srv.headersTimeout=15000;
 setInterval(flush,300).unref();setInterval(sendPres,6000).unref();
 const bye=async()=>{await flush();process.exit(0)};process.on('SIGINT',bye);process.on('SIGTERM',bye);
 srv.listen(cfg.port,()=>console.log(`Aethra server on :${cfg.port} · db=${db.driver} · users=${Object.keys(S.users).length}`+(cfg.devHash?'':' · dev unlock DISABLED (set DEV_SALT/DEV_HASH)')))}
main().catch(e=>{console.error(e);process.exit(1)});
module.exports={cfg};
