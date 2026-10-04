'use strict';
/* One tiny storage interface, two drivers:
   - SQLite  (default, built into Node 22+, no npm install, file on disk)
   - PostgreSQL (set DATABASE_URL, needs `npm i pg`)                                  */
const fs=require('fs'),path=require('path');
const SCHEMA=(pg)=>`
CREATE TABLE IF NOT EXISTS docs(coll TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,updated BIGINT NOT NULL,PRIMARY KEY(coll,id));
CREATE TABLE IF NOT EXISTS auth(uid TEXT PRIMARY KEY,name TEXT NOT NULL,name_lc TEXT NOT NULL UNIQUE,pass TEXT NOT NULL,created BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY,uid TEXT NOT NULL,created BIGINT NOT NULL,expires BIGINT NOT NULL,ip TEXT,ua TEXT);
CREATE INDEX IF NOT EXISTS sessions_uid ON sessions(uid);
CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,uid TEXT NOT NULL,mime TEXT NOT NULL,anim INTEGER NOT NULL,kind TEXT,size INTEGER NOT NULL,bytes ${pg?'BYTEA':'BLOB'} NOT NULL,created BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS uploads_uid ON uploads(uid);
CREATE TABLE IF NOT EXISTS audit(id ${pg?'BIGSERIAL PRIMARY KEY':'INTEGER PRIMARY KEY AUTOINCREMENT'},ts BIGINT NOT NULL,actor TEXT,action TEXT NOT NULL,target TEXT,meta TEXT);`;
async function open(cfg){
 let exec,pg=!!cfg.dbUrl;
 if(pg){const{Pool}=require('pg');const pool=new Pool({connectionString:cfg.dbUrl,ssl:/localhost|127\.0\.0\.1/.test(cfg.dbUrl)?false:{rejectUnauthorized:false}});
  exec=async(sql,params=[])=>{let i=0;const r=await pool.query(sql.replace(/\?/g,()=>'$'+(++i)),params);return r.rows};
  for(const s of SCHEMA(true).split(';').map(x=>x.trim()).filter(Boolean))await exec(s)}
 else{const{DatabaseSync}=require('node:sqlite');fs.mkdirSync(cfg.dataDir,{recursive:true});const db=new DatabaseSync(path.join(cfg.dataDir,'aethra.db'));
  db.exec('PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;');db.exec(SCHEMA(false));
  exec=async(sql,params=[])=>{const st=db.prepare(sql);return/^\s*select/i.test(sql)?st.all(...params):(st.run(...params),[])}}
 const n=x=>Number(x);
 return{
  driver:pg?'postgres':'sqlite',
  async loadDocs(){return(await exec('SELECT coll,id,data FROM docs')).map(r=>({c:r.coll,id:r.id,data:JSON.parse(r.data)}))},
  putDoc:(c,id,d)=>exec('INSERT INTO docs(coll,id,data,updated) VALUES(?,?,?,?) ON CONFLICT(coll,id) DO UPDATE SET data=excluded.data,updated=excluded.updated',[c,id,JSON.stringify(d),Date.now()]),
  delDoc:(c,id)=>exec('DELETE FROM docs WHERE coll=? AND id=?',[c,id]),
  async authByName(lc){return(await exec('SELECT * FROM auth WHERE name_lc=?',[lc]))[0]},
  async authByUid(uid){return(await exec('SELECT * FROM auth WHERE uid=?',[uid]))[0]},
  createAuth:(uid,name,pass)=>exec('INSERT INTO auth(uid,name,name_lc,pass,created) VALUES(?,?,?,?,?)',[uid,name,name.toLowerCase(),pass,Date.now()]),
  renameAuth:(uid,name)=>exec('UPDATE auth SET name=?,name_lc=? WHERE uid=?',[name,name.toLowerCase(),uid]),
  delAuth:uid=>exec('DELETE FROM auth WHERE uid=?',[uid]),
  putSession:(th,uid,exp,ip,ua)=>exec('INSERT INTO sessions(th,uid,created,expires,ip,ua) VALUES(?,?,?,?,?,?)',[th,uid,Date.now(),exp,ip,String(ua||'').slice(0,200)]),
  async getSession(th){const r=(await exec('SELECT uid,expires FROM sessions WHERE th=?',[th]))[0];return r&&{uid:r.uid,expires:n(r.expires)}},
  delSession:th=>exec('DELETE FROM sessions WHERE th=?',[th]),delSessionsOf:uid=>exec('DELETE FROM sessions WHERE uid=?',[uid]),
  purgeSessions:()=>exec('DELETE FROM sessions WHERE expires<?',[Date.now()]),
  putUpload:(id,uid,mime,anim,kind,buf)=>exec('INSERT INTO uploads(id,uid,mime,anim,kind,size,bytes,created) VALUES(?,?,?,?,?,?,?,?)',[id,uid,mime,anim?1:0,kind||'',buf.length,buf,Date.now()]),
  async getUpload(id){const r=(await exec('SELECT mime,bytes FROM uploads WHERE id=?',[id]))[0];return r&&{mime:r.mime,bytes:Buffer.from(r.bytes)}},
  async uploadMeta(){return(await exec('SELECT id,uid,anim FROM uploads')).map(r=>({id:r.id,uid:r.uid,anim:!!n(r.anim)}))},
  async uploadStats(uid){const r=(await exec('SELECT COUNT(*) AS c,COALESCE(SUM(size),0) AS s FROM uploads WHERE uid=?',[uid]))[0];return{count:n(r.c),bytes:n(r.s)}},
  delUploadsOf:uid=>exec('DELETE FROM uploads WHERE uid=?',[uid]),
  log:(actor,action,target,meta)=>exec('INSERT INTO audit(ts,actor,action,target,meta) VALUES(?,?,?,?,?)',[Date.now(),actor||'',action,target||'',JSON.stringify(meta||{})]).catch(()=>{})
 }}
module.exports={open,SCHEMA};
