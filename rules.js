'use strict';
/* Authorization rules: every client write is an op {c,id,p,o,v}. Nothing is trusted;
   each op is checked against the committed state + the actor's server-side rank/permissions. */
const P={ADMIN:1,CH:2,KICK:4,BAN:8,TO:16,MSG:32,SEND:64,VIEW:128,ROLES:256,ATTACH:512,PING:1024};
const ID=/^[A-Za-z0-9_-]{3,48}$/,HEX=/^#[0-9a-fA-F]{6}$/,BAD=new Set(['__proto__','constructor','prototype']);
const isObj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v),str=(v,a,b)=>typeof v==='string'&&v.length>=a&&v.length<=b;
const keysOk=(o,allowed)=>isObj(o)&&Object.keys(o).every(k=>allowed.includes(k));
function dirty(v,d=0){if(d>9)return true;if(typeof v==='string')return v.length>20000;if(v===null||typeof v!=='object')return typeof v==='function'||(typeof v==='number'&&!Number.isFinite(v));
 if(Array.isArray(v))return v.length>3000||v.some(x=>dirty(x,d+1));const k=Object.keys(v);return k.length>400||k.some(x=>BAD.has(x)||dirty(v[x],d+1))}
const aur=(u,now)=>!!(u&&u.aurum&&(!u.aurum.until||u.aurum.until>now));
const rankOf=(S,u)=>{const p=u&&u.pos&&S.plat.pos[u.pos];return p?p.rank:0};
const perms=(g,u)=>{const m=g.mem[u];return m?m.roles.reduce((a,id)=>a|((g.roles.find(r=>r.id===id)||{}).perm||0),0):0};
const isOwner=(g,u)=>g.owner===u,can=(g,u,p)=>!!g.mem[u]&&(isOwner(g,u)||!!(perms(g,u)&1)||!!(perms(g,u)&p));
const topIdx=(g,u)=>{const m=g.mem[u];const i=g.roles.findIndex(r=>m.roles.includes(r.id));return i<0?g.roles.length:i};
const above=(g,a,b)=>a!==b&&b!==g.owner&&!!g.mem[b]&&(isOwner(g,a)||topIdx(g,a)<topIdx(g,b));
const lvl=(g,S,now)=>{let n=0;for(const[u,c]of Object.entries(g.pulses||{}))if(aur(S.users[u],now))n+=Math.min(+c||0,2);return n>=14?3:n>=7?2:n>=2?1:0};
function chPerm(g,u,ch,k){if(!g.mem[u])return false;if(isOwner(g,u)||perms(g,u)&1)return true;
 const b={view:P.VIEW,send:P.SEND,attach:P.ATTACH,ping:P.PING}[k],ow=ch.ow||{};let ok=!!(perms(g,u)&b);
 if(ow.e&&ow.e[k]!==undefined)ok=!!ow.e[k];let a=0,d=0;g.mem[u].roles.forEach(r=>{const v=ow[r]&&ow[r][k];if(v===1)a=1;if(v===0)d=1});
 const base=a?true:d?false:ok;if(k!=='view')return base;
 return base&&(!ch.priv||can(g,u,P.MSG)||can(g,u,P.KICK)||g.mem[u].roles.some(r=>ow[r]&&ow[r].view===1))}
function okImg(c,v,o={}){if(typeof v!=='string')return false;const m=/^\/uploads\/([a-f0-9]{24})\.(png|jpg|gif|webp)$/.exec(v);
 if(m){const up=c.upload(m[1]);return !!up&&up.uid===c.uid&&(!up.anim||!!o.anim)}return !!o.https&&/^https:\/\/[^\s'"()<>]{4,300}$/.test(v)}
const canAnim=(c,u)=>aur(u,c.now)||rankOf(c.S,u)>=3;

/* ---------- users ---------- */
const SELF_SIMPLE={color:HEX,banner:HEX,banner2:HEX,accent:HEX};
function rUsers(c,op){const{id,p,o}=op,A=c.uid,f=p[0];
 if(!p.length)return'use the API';
 const T=c.get('users',id);if(!T)return'no user';
 if(id!==A){ // cross-user writes
  if(f==='aurum'){if(o==='set')return c.rank>=4&&isObj(op.v)&&Number.isFinite(op.v.until)&&(op.v.until===0||op.v.until>c.now)&&!(T.noAurum&&(!T.noAurum.until||T.noAurum.until>c.now))?(op.v={until:op.v.until,by:A},null):'only the developer can grant Aurum';
   return o==='del'&&c.rank>=3?null:'rank'}
  if(f==='noAurum')return c.rank>=3&&(o==='del'||(o==='set'&&isObj(op.v)&&Number.isFinite(op.v.until)))?null:'rank';
  if(f==='pos'){if(c.rank<4)return'only the developer';return o==='del'||(o==='set'&&c.S.plat.pos[op.v])?null:'bad position'}
  if(f==='gb')return c.rank>=4&&(op.o==='sadd'&&c.S.plat.badges[op.v]||op.o==='srm')?null:'rank';
  if(['inc','out','fr'].includes(f)&&p.length===1){
   if(op.v!==A)return'only your own id';
   if(o==='srm')return null;
   if(o!=='sadd')return'bad';
   if(f==='inc')return T.pv&&T.pv.fr!==0&&!(T.bl||[]).includes(A)&&!(c.get('users',A).bl||[]).includes(id)&&(T.inc||[]).length<200?null:'requests closed';
   if(f==='fr'){const oa=c.orig('users',A),ot=c.orig('users',id);return oa&&ot&&(ot.inc||[]).includes(A)&&(oa.out||[]).includes(id)?null:'no pending request'}
   return'denied'}
  return'cannot edit other users'}
 // self writes
 if(['id','hash','ts','early','founder','pos','aurum','noAurum','gb'].includes(f))return'protected field';
 if(f==='name'){return str(op.v,3,20)&&c.nameFree(op.v,A)?null:'name taken or invalid'}
 if(SELF_SIMPLE[f])return SELF_SIMPLE[f].test(op.v)?null:'bad color';
 if(f==='bio')return str(op.v,0,190)?null:'bad';if(f==='pron')return str(op.v,0,20)?null:'bad';if(f==='custom')return str(op.v,0,60)?null:'bad';
 if(f==='status')return['online','idle','dnd','invisible'].includes(op.v)?null:'bad';
 if(f==='theme')return['dark','light','midnight'].includes(op.v)?null:'bad';if(f==='lang')return['ru','en'].includes(op.v)?null:'bad';
 if(['dev','test','rl'].includes(f))return typeof op.v==='boolean'?null:'bad';
 if(f==='img'||f==='bimg'){if(o==='del')return null;return okImg(c,op.v,{anim:canAnim(c,T)})?null:'invalid image'}
 if(f==='nstyle'){if(o==='del')return null;return aur(T,c.now)&&isObj(op.v)&&keysOk(op.v,['f','e','c'])&&Number.isInteger(op.v.f)&&op.v.f>=0&&op.v.f<12&&['min','grad','neon','multi','hl','gamma','prism'].includes(op.v.e)&&HEX.test(op.v.c)?null:'Aurum required'}
 if(f==='tagFrom'){if(o==='del')return null;const g=c.S.srv[op.v];return g&&g.mem[A]&&g.tag&&lvl(g,c.S,c.now)>=2?null:'invalid server tag'}
 if(['nf','pv','ui','vs','notes','read','mread'].includes(f))return JSON.stringify(op.v===undefined?0:op.v).length<20000?null:'too large';
 if(['ig','bl'].includes(f)&&p.length===1)return(o==='sadd'||o==='srm')&&typeof op.v==='string'&&c.S.users[op.v]?null:'bad';
 if(f==='inc')return o==='srm'?null:'only others can add requests';
 if(f==='out'&&p.length===1){if(o==='srm')return null;const X=c.S.users[op.v];return o==='sadd'&&X&&op.v!==A&&X.pv&&X.pv.fr!==0&&!(X.bl||[]).includes(A)&&!(T.bl||[]).includes(op.v)&&(T.out||[]).length<100&&!(T.fr||[]).includes(op.v)?null:'cannot send request'}
 if(f==='fr'&&p.length===1){if(o==='srm')return null;const oa=c.orig('users',A),ox=c.orig('users',op.v);return o==='sadd'&&ox&&(oa.inc||[]).includes(op.v)&&(ox.out||[]).includes(A)?null:'no pending request'}
 return'denied'}

/* ---------- direct messages ---------- */
function reOnly(c,op,idx,old){const A=c.uid,p=op.p,o=op.o,rel=p.slice(idx);   // rel = ['re', emoji?]
 if(rel.length===1)return o==='set'&&isObj(op.v)&&Object.keys(op.v).length<=12&&Object.entries(op.v).every(([e,a])=>e.length<=8&&Array.isArray(a)&&a.every(x=>x===A))?null:'reactions: own only';
 if(rel.length===2){if(o==='set')return str(rel[1],1,8)&&Array.isArray(op.v)&&op.v.every(x=>x===A)?null:'own only';
  if(o==='del')return((old&&old.re&&old.re[rel[1]])||[]).every(x=>x===A)?null:'own only';
  if(o==='sadd'||o==='srm')return op.v===A?null:'own only'}return'denied'}
function msgBody(c,m,op,limit){const A=c.uid;if(!isObj(m)||!keysOk(m,['id','u','t','ts','att','rt','mock']))return'bad message';if(!ID.test(m.id)||m.u!==A)return'bad author';
 if(typeof m.t!=='string'||m.t.length>limit)return'too long';if(!m.t.trim()&&!m.att)return'empty';
 if(m.att){if(!isObj(m.att)||!str(m.att.n,1,120)||!/^\/uploads\/[a-f0-9]{24}\.\w{2,5}$/.test(m.att.d||'')||!c.upload(m.att.d.slice(9,33)))return'bad attachment'}
 if(m.rt!==undefined&&!str(m.rt,3,48))return'bad reply';
 if(!c.rate('msg:'+A,8,10000))return'slow down';m.ts=c.now;return null}
function dmCheck(c,key,m){const[a,b]=key.split('_'),A=c.uid,OU=c.S.users[a===A?b:a],me=c.S.users[A];
 if(!OU)return'no user';if((OU.bl||[]).includes(A)||(me.bl||[]).includes(OU.id))return'blocked';if(OU.pv&&OU.pv.dm===0&&!(OU.fr||[]).includes(A))return'DMs closed';return null}
function rDm(c,op){const{id:key,p,o}=op,A=c.uid,parts=key.split('_');
 if(parts.length!==2||!parts.includes(A)||!parts.every(x=>c.S.users[x])||parts[0]>parts[1])return'not a participant';
 const list=c.get('dm',key);
 if(!p.length){if(o==='set'&&!list&&Array.isArray(op.v)&&op.v.length<=1){if(!op.v.length)return null;const e=dmCheck(c,key);return e||msgBody(c,op.v[0],op,4000)}return'denied'}
 if(!list)return'no thread';
 if(p.length===1&&p[0]==='')return'bad';
 if(p.length===0)return'bad';
 return null}
function rDmOp(c,op){const key=op.id,A=c.uid,list=c.get('dm',key);
 if(!op.p.length){const e=rDm(c,op);return e}
 const e0=rDm(c,{...op,p:[],o:'noop'});if(e0&&e0!=='denied')return e0;if(!list)return'no thread';
 if(op.p.length===0)return'bad';
 if(op.o==='add'&&op.p.length===0){}
 return null}
function rDmFull(c,op){const key=op.id,A=c.uid,parts=key.split('_');
 if(parts.length!==2||!parts.includes(A)||!parts.every(x=>c.S.users[x])||parts[0]>parts[1])return'not a participant';
 const list=c.get('dm',key);
 if(!op.p.length){if(op.o==='set'&&!list&&Array.isArray(op.v)&&op.v.length<=1){if(!op.v.length)return null;return dmCheck(c,key)||msgBody(c,op.v[0],op,4000)}return'denied'}
 if(!list)return'no thread';
 if(op.p.length===0)return'bad';
 if(op.o==='add'&&!op.p.length)return'bad';
 return null}
function rDmOps(c,op){const A=c.uid,key=op.id;const base=rDmFull(c,{...op});if(!op.p.length)return base;if(base)return base;
 const list=c.get('dm',key),p=op.p,o=op.o;
 if(!p.length)return'bad';
 return null}

/* generic message-list ops (dm threads, server channels). `rel` is the path inside the list. */
function listOps(c,op,rel,list,o2){const A=c.uid,{o}=op,mod=o2.mod;
 if(!rel.length){
  if(o==='add'){const e=o2.pre&&o2.pre();return e||msgBody(c,op.v,op,4000)}
  if(o==='rm'){const m=list.find(x=>x.id===op.id);return m&&(m.u===A||mod)?null:'denied'}
  return'denied'}
 if(rel[0][0]!=='#')return'bad';const m=list.find(x=>x.id===rel[0].slice(1));if(!m)return'no message';const f=rel[1];
 if(f==='t')return m.u===A&&o==='set'&&str(op.v,1,4000)?null:'author only';
 if(f==='ed')return m.u===A&&op.v===1?null:'author only';
 if(f==='re')return reOnly(c,op,op.p.length-rel.length+1,m);
 return'denied'}
function rDmReal(c,op){const e=rDmFull(c,op);if(e||!op.p.length)return e;const list=c.get('dm',op.id);
 return listOps(c,op,op.p,list,{mod:false,pre:()=>dmCheck(c,op.id)})}

/* ---------- servers ---------- */
function newSrv(c,op){const v=op.v,A=c.uid;
 if(!isObj(v)||!ID.test(op.id)||v.id!==op.id||v.owner!==A||!str(v.name,1,40))return'bad server';
 if(!isObj(v.mem)||Object.keys(v.mem).join()!==A)return'bad members';
 if(!Array.isArray(v.roles)||v.roles.length<1||v.roles.length>6||!v.roles.every(r=>isObj(r)&&ID.test(r.id)&&str(r.name,1,30)&&HEX.test(r.color)&&Number.isInteger(r.perm)&&r.perm>=0&&r.perm<=0x7FF))return'bad roles';
 if(!v.roles.some(r=>r.perm&1)||!v.mem[A].roles.every(r=>v.roles.some(x=>x.id===r)))return'bad roles';
 if(!Array.isArray(v.ch)||v.ch.length>12||!Array.isArray(v.cats)||v.cats.length>6)return'bad channels';
 for(const k of['bans','audit','events'])if(!Array.isArray(v[k])||v[k].length)return'must be empty';
 for(const k of['invites','voice','pulses'])if(v[k]!==undefined&&Object.keys(v[k]).length)return'must be empty';
 for(const k of['icon','banner','tag','vanity','ibg'])if(v[k]!==undefined)return'locked feature';
 if(Object.values(c.S.srv).filter(s=>s.owner===A).length>=15)return'server limit';
 return dirty(v)?'bad data':null}
function rSrv(c,op){const{id,p,o}=op,A=c.uid,now=c.now,g=c.get('srv',id);
 if(!p.length){if(o==='set')return g?'exists':newSrv(c,op);if(o==='del')return!g?'not found':(g.owner===A||c.rank>=3)?null:'owner only';return'bad'}
 if(!g)return'no server';if(!g.mem[A])return'not a member';
 const f=p[0],L=lvl(g,c.S,now),pm=x=>can(g,A,x),CH=pm(P.CH);
 switch(f){
 case'name':return CH&&str(op.v,1,40)?null:'denied';
 case'desc':return CH&&(o==='del'||str(op.v,0,200))?null:'denied';
 case'color':return CH&&HEX.test(op.v)?null:'denied';
 case'mute':case'hideDm':return typeof op.v==='boolean'?null:'bad';
 case'bar':return CH&&typeof op.v==='boolean'?null:'denied';
 case'icon':case'banner':case'ibg':{if(!CH)return'denied';if(o==='del')return null;const own=c.S.users[g.owner];
  if(f==='banner'&&L<1&&!canAnim(c,own))return'needs Pulse Lv1';if(f==='ibg'&&L<1)return'needs Pulse Lv1';
  return okImg(c,op.v,{anim:L>=2||canAnim(c,own)})?null:'invalid image'}
 case'tag':if(!CH)return'denied';if(o==='del')return null;return L>=2&&isObj(op.v)&&keysOk(op.v,['t','i','c'])&&/^[A-Za-z0-9]{2,4}$/.test(op.v.t)&&str(op.v.i,1,8)&&HEX.test(op.v.c)?null:'needs Pulse Lv2';
 case'vanity':if(!CH)return'denied';if(o==='del')return null;return L>=3&&/^[a-z0-9-]{3,24}$/.test(op.v)&&!c.get('inv',op.v)?null:'needs Pulse Lv3 / taken';
 case'pulses':{if(p.length!==2||p[1]!==A)return'own pulses only';const n=o==='del'?0:op.v;if(!Number.isInteger(n)||n<0||n>2||!aur(c.S.users[A],now))return'Aurum required';
  const used=Object.values(c.S.srv).reduce((a,s)=>a+(s.id===id?0:((s.pulses||{})[A]||0)),0);return used+n<=2?null:'no free pulses'}
 case'owner':case'invites_':return'denied';
 case'roles':return rRoles(c,g,op,L);
 case'mem':return rMem(c,g,op);
 case'cats':return CH&&(p.length===1?(o==='add'?(str(op.v&&op.v.name,1,40)&&ID.test(op.v.id)&&g.cats.length<12?null:'bad'):null):(p[2]==='name'||p[2]==='fold')?null:'denied'):'denied';
 case'ch':return rCh(c,g,op,L);
 case'bans':return pm(P.BAN)&&(o==='sadd'||o==='srm')&&typeof op.v==='string'&&op.v!==g.owner&&(o==='srm'||!c.orig('srv',id).mem[op.v]||above(c.orig('srv',id),A,op.v))?null:'denied';
 case'audit':return o==='add'&&p.length===1&&(pm(P.KICK)||pm(P.BAN)||pm(P.TO)||pm(P.MSG)||pm(P.CH)||pm(P.ROLES))&&isObj(op.v)&&keysOk(op.v,['id','a','by','tg','ts'])&&ID.test(op.v.id)&&str(op.v.a,1,40)&&str(op.v.by,0,60)&&str(op.v.tg||'',0,80)?null:'denied';
 case'invites':{if(p.length!==2)return o==='set'&&p.length===1&&isObj(op.v)&&!Object.keys(op.v).length?null:'denied';const code=p[1];
  if(o==='set')return/^[a-z0-9]{6,24}$/.test(code)&&isObj(op.v)&&op.v.by===A&&op.v.uses===0&&!c.S.inv[code]?null:'bad invite';
  if(o==='del'){const i=g.invites[code];return i&&(i.by===A||CH)?null:'denied'}return'denied'}
 case'events':return CH&&(o==='rm'||(o==='add'&&isObj(op.v)&&ID.test(op.v.id)&&str(op.v.name,1,60)&&Number.isFinite(op.v.ts)&&g.events.length<50))?null:'denied';
 case'pins':return pm(P.MSG)&&(p.length===2?(o==='sadd'||o==='srm')&&ID.test(op.v):(p.length===1&&o==='set'&&isObj(op.v)&&JSON.stringify(op.v).length<4000))?null:'denied';
 case'voice':{if(p.length===1)return o==='set'&&isObj(op.v)&&Object.values(op.v).every(a=>Array.isArray(a)&&a.every(x=>x===A))?null:'denied';
  const ch=g.ch.find(x=>x.id===p[1]);if(!ch||ch.type!=='voice'||!chPerm(g,A,ch,'view'))return'denied';
  if(o==='set')return Array.isArray(op.v)&&op.v.every(x=>x===A)?null:'own only';return(o==='sadd'||o==='srm')&&op.v===A?null:'own only'}
 case'msgs':return rMsgs(c,g,op);
 case'posts':return rPosts(c,g,op);
 }
 return'denied by default'}
function rRoles(c,g,op,L){const{p,o}=op,A=c.uid;if(!can(g,A,P.ROLES))return'need Manage Roles';
 const own=isOwner(g,A),myTop=topIdx(g,A),mine=(own||(perms(g,A)&1))?0x7FF:perms(g,A);
 const below=rid=>{const i=g.roles.findIndex(r=>r.id===rid);return i>=0&&(own||i>myTop)};
 if(p.length===1){
  if(o==='add'){const r=op.v;return isObj(r)&&keysOk(r,['id','name','color','perm','badge','m3'])&&ID.test(r.id)&&str(r.name,1,30)&&HEX.test(r.color)&&Number.isInteger(r.perm)&&r.perm>=0&&!(r.perm&~mine)&&g.roles.length<30&&op.at===-1?null:'bad role'}
  if(o==='rm')return below(op.id)&&g.roles.length>1?null:'hierarchy';
  if(o==='ord'){const cur=g.roles.map(r=>r.id);for(let i=0;!own&&i<=Math.min(myTop,cur.length-1);i++)if(op.ids[i]!==cur[i])return'hierarchy';return op.ids.length===cur.length&&new Set(op.ids).size===cur.length&&op.ids.every(i=>cur.includes(i))?null:'bad order'}
  return'denied'}
 if(!below(p[1].slice(1)))return'hierarchy';const f=p[2],r=g.roles.find(x=>x.id===p[1].slice(1));
 if(o==='del')return['color2','glow','icon','badge','style'].includes(f)?null:'denied';
 switch(f){
 case'perm':return Number.isInteger(op.v)&&op.v>=0&&op.v<=0x7FF&&!((op.v&~r.perm)&~mine)?null:'perm escalation';
 case'name':return str(op.v,1,30)?null:'bad';case'color':return HEX.test(op.v)?null:'bad';
 case'color2':return HEX.test(op.v)&&L>=1?null:'needs Pulse Lv1';
 case'badge':return str(op.v,0,8)?null:'bad';case'glow':case'm3':return op.v===1||op.v===true?null:'bad';
 case'style':return op.v==='solid'||(op.v==='gradient'&&L>=1)||(op.v==='holo'&&L>=2)?null:'needs Pulse level';
 case'icon':return L>=2&&okImg(c,op.v,{anim:false})?null:'needs Pulse Lv2'}
 return'denied'}
function rMem(c,g,op){const{p,o}=op,A=c.uid,u=p[1];
 if(p.length===1)return'use the API';
 if(p.length===2){if(o!=='del')return'use the API';if(u===A)return A===g.owner?'owner cannot leave':null;return(can(g,A,P.KICK)||can(g,A,P.BAN))&&above(c.orig('srv',g.id),A,u)?null:'denied'}
 const m=g.mem[u];if(!m)return'no member';const f=p[2];
 if(f==='nick')return u===A&&(o==='del'||str(op.v,0,32))?null:'denied';
 if(f==='ns')return u===A&&(o==='del'||['','grad','neon','shimmer','rainbow'].includes(op.v))?null:'denied';
 if(f==='to')return can(g,A,P.TO)&&above(g,A,u)&&Number.isFinite(op.v)&&op.v>=0&&op.v<=c.now+28*864e5?null:'denied';
 if(f==='roles'&&(o==='sadd'||o==='srm')){const r=g.roles.find(x=>x.id===op.v);if(!r||!can(g,A,P.ROLES))return'denied';const own=isOwner(g,A);
  if(!own&&g.roles.indexOf(r)<=topIdx(g,A))return'hierarchy';if(u!==A&&!own&&!above(g,A,u))return'hierarchy';return o==='srm'&&m.roles.length<=1?'last role':null}
 return'denied'}
function chShape(x){return isObj(x)&&keysOk(x,['id','name','type','cat','slow','priv','ow','tags','reqTag','topic'])&&ID.test(x.id)&&str(x.name,1,40)&&['text','voice','forum'].includes(x.type)&&!dirty(x)}
function owOk(v){return isObj(v)&&Object.values(v).every(r=>isObj(r)&&Object.entries(r).every(([k,x])=>['view','send','attach','ping'].includes(k)&&(x===0||x===1)))}
function rCh(c,g,op,L){const{p,o}=op;if(!can(g,c.uid,P.CH))return'need Manage Channels';
 if(p.length===1){if(o==='add')return chShape(op.v)&&g.ch.length<60&&(!op.v.ow||owOk(op.v.ow))?null:'bad channel';return o==='rm'||o==='ord'?null:'denied'}
 const f=p[2];if(o==='del')return['topic','cat','priv','reqTag','tags','ow'].includes(f)||p.length>3?null:'denied';
 if(f==='name'||f==='topic')return str(op.v,1,40)?null:'bad';if(f==='slow')return Number.isInteger(op.v)&&op.v>=0&&op.v<=21600?null:'bad';
 if(f==='cat')return op.v===null||g.cats.some(k=>k.id===op.v)?null:'bad';if(f==='priv'||f==='reqTag')return op.v===1||op.v===0||typeof op.v==='boolean'?null:'bad';
 if(f==='ow'){if(p.length===3)return owOk(op.v)?null:'bad';if(p.length===5)return(op.v===0||op.v===1)&&['view','send','attach','ping'].includes(p[4])?null:'bad';if(p.length===4)return owOk({[p[3]]:op.v})?null:'bad';return'denied'}
 if(f==='tags'){const tg=x=>isObj(x)&&keysOk(x,['id','name','emoji','color'])&&ID.test(x.id)&&str(x.name,1,20)&&str(x.emoji||'',0,8)&&HEX.test(x.color);
  if(p.length===3)return o==='set'&&Array.isArray(op.v)&&op.v.length<=20&&op.v.every(tg)?null:o==='add'?(tg(op.v)?null:'bad'):o==='rm'?null:'denied';return'denied'}
 return'denied'}
function rMsgs(c,g,op){const{p,o}=op,A=c.uid,cid=p[1],ch=g.ch.find(x=>x.id===cid);
 if(p.length<2||!ch||ch.type!=='text')return'no channel';if(!chPerm(g,A,ch,'view'))return'cannot view';
 const mod=can(g,A,P.MSG),list=g.msgs[cid];
 const pre=m=>()=>{if(!chPerm(g,A,ch,'send'))return'no send permission';if(g.mem[A].to>c.now)return'timed out';
  const mm=m||{};if(mm.att&&!chPerm(g,A,ch,'attach'))return'no attach permission';
  const tx=(mm.t||'').toLowerCase();if(!chPerm(g,A,ch,'ping')){if(/@(everyone|here)\b/.test(tx))return'no ping permission';for(const u of Object.keys(g.mem))if(u!==A&&c.S.users[u]&&tx.includes('@'+c.S.users[u].name.toLowerCase()))return'no ping permission'}
  if(ch.slow&&!mod){const l=(list||[]).filter(x=>x.u===A).pop();if(l&&c.now-l.ts<ch.slow*1000)return'slowmode'}return null};
 if(p.length===2&&o==='set'&&!list&&Array.isArray(op.v)&&op.v.length===1){const e=pre(op.v[0])();return e||msgBody(c,op.v[0],op,4000)}
 if(!list)return'no list';
 if(p.length===2&&o==='add'){const e=pre(op.v)();return e||msgBody(c,op.v,op,4000)}
 return listOps(c,op,p.slice(2),list,{mod,pre:null})}
function rPosts(c,g,op){const{p,o}=op,A=c.uid,cid=p[1],ch=g.ch.find(x=>x.id===cid);
 if(p.length<2||!ch||ch.type!=='forum')return'no forum';if(!chPerm(g,A,ch,'view'))return'cannot view';
 const mod=can(g,A,P.MSG),list=g.posts[cid],canSend=chPerm(g,A,ch,'send')&&g.mem[A].to<=c.now;
 const postOk=po=>{if(!isObj(po)||!keysOk(po,['id','u','title','body','ts','replies','tags','likes'])||!ID.test(po.id)||po.u!==A||!str(po.title,1,120)||typeof po.body!=='string'||po.body.length>4000)return'bad post';
  if(!Array.isArray(po.replies)||po.replies.length||(po.likes||[]).length)return'bad post';const tg=ch.tags||[];if((po.tags||[]).length>3||!(po.tags||[]).every(i=>tg.some(x=>x.id===i)))return'bad tags';if(ch.reqTag&&!(po.tags||[]).length)return'tag required';
  if(!canSend)return'cannot post';if(!c.rate('post:'+A,5,60000))return'slow down';po.ts=c.now;return null};
 if(p.length===2){
  if(o==='set'&&!list&&Array.isArray(op.v)&&op.v.length===1)return postOk(op.v[0]);
  if(!list)return'no list';if(o==='add')return postOk(op.v);
  if(o==='rm'){const po=list.find(x=>x.id===op.id);return po&&(po.u===A||mod)?null:'denied'}return'denied'}
 if(!list)return'no list';const po=list.find(x=>x.id===(p[2]||'').slice(1));if(!po)return'no post';const f=p[3];
 if(p.length===4){
  if(f==='pin'||f==='lock')return mod&&typeof op.v==='boolean'?null:'moderators only';
  if(f==='likes'){return o==='set'?(Array.isArray(op.v)&&op.v.every(x=>x===A)?null:'own only'):(o==='sadd'||o==='srm')&&op.v===A?null:'own only'}
  if(f==='title')return po.u===A&&str(op.v,1,120)?null:'author only';if(f==='body')return po.u===A&&typeof op.v==='string'&&op.v.length<=4000?null:'author only';
  if(f==='replies'){if(o==='add'){const r=op.v;if(po.lock)return'locked';if(!canSend)return'cannot reply';if(!isObj(r)||!keysOk(r,['id','u','t','ts'])||!ID.test(r.id)||r.u!==A||!str(r.t,1,4000))return'bad reply';if(!c.rate('msg:'+A,8,10000))return'slow down';r.ts=c.now;return null}
   if(o==='rm'){const r=po.replies.find(x=>x.id===op.id);return r&&(r.u===A||mod)?null:'denied'}}
 }
 return'denied'}

/* ---------- invites / platform ---------- */
function rInv(c,op){const code=op.id,A=c.uid;if(!/^[a-z0-9-]{3,24}$/.test(code))return'bad code';
 if(op.o==='set'&&!op.p.length){const g=c.get('srv',op.v);if(!g||!g.mem[A])return'denied';return(g.invites&&g.invites[code]&&g.invites[code].by===A)||(g.vanity===code&&can(g,A,P.CH))?null:'invite not registered'}
 if(op.o==='del'&&!op.p.length){const sid=c.S.inv[code],g=sid&&c.get('srv',sid);return c.rank>=3||!g||(!g.invites[code]&&g.vanity!==code)?null:'denied'}return'denied'}
function rPlat(c,op){const{p,o}=op,A=c.uid,R=c.rank,f=p[0];if(!f)return'denied';
 if(f==='ann')return R>=3&&(o==='del'||(o==='set'&&str(op.v,0,200)))?null:'rank 3 required';
 if(f==='pos'||f==='badges'){if(R<4)return'only the developer';
  const img=x=>!x||/^\/uploads\//.test(x)||/^https:\/\/[^\s'"()<>]{4,300}$/.test(x)||x.length<=8;
  if(p.length===2&&o==='set'){const v=op.v;if(!isObj(v)||!str(v.name,1,30)||!(f==='pos'?(Number.isInteger(v.rank)&&v.rank>=0&&v.rank<=3&&img(v.badge)&&HEX.test(v.color)):(HEX.test(v.color)&&(!v.img||img(v.img)))))return'bad';if(f==='pos'&&c.S.plat.pos[p[1]]&&c.S.plat.pos[p[1]].sys&&v.rank!==c.S.plat.pos[p[1]].rank)return'system rank is fixed';return dirty(v)?'bad':null}
  if(p.length===3&&o==='set'){if(f==='pos'&&p[2]==='rank')return'rank is fixed after creation';return dirty(op.v)?'bad':null}
  if(p.length===2&&o==='del'){return f==='pos'&&c.S.plat.pos[p[1]]&&c.S.plat.pos[p[1]].sys?'system position':null}return'denied'}
 if(f==='bans'){if(R<2)return'rank 2 required';const t=c.S.users[p[1]];if(o==='del')return null;
  if(o==='set'&&p.length===2&&t&&isObj(op.v)&&rankOf(c.S,t)<R&&p[1]!==A){if(!op.v.until&&R<3)return'only admins can ban forever';op.v={until:+op.v.until||0,reason:String(op.v.reason||'').slice(0,100),by:A};return null}return'denied'}
 if(f==='tickets'){const tk=c.get('plat','').tickets;
  if(p.length===1){if(o==='add'){const t=op.v;if(!isObj(t)||t.uid!==A||t.status!=='open'||!ID.test(t.id)||!str(t.subj,1,100)||!str(t.cat,1,30)||t.as||!Array.isArray(t.msgs)||t.msgs.length!==1)return'bad ticket';const m=t.msgs[0];if(!isObj(m)||m.u!==A||!str(m.t,1,4000)||!ID.test(m.id))return'bad ticket';if(tk.filter(x=>x.uid===A&&x.status!=='closed').length>=10)return'too many open tickets';if(!c.rate('tk:'+A,3,60000))return'slow down';t.ts=c.now;m.ts=c.now;m.staff=false;return null}return'denied'}
  const t=tk.find(x=>x.id===p[1].slice(1));if(!t)return'no ticket';const staff=R>=1;
  if(!staff&&t.uid!==A)return'not your ticket';
  if(p.length===3&&p[2]==='msgs'&&o==='add'){const m=op.v;if(!isObj(m)||m.u!==A||!str(m.t,1,4000)||!ID.test(m.id)||t.status==='closed'&&!staff)return'bad';if(!c.rate('tk:'+A,10,60000))return'slow down';m.ts=c.now;m.staff=staff&&t.uid!==A;return null}
  if(p.length===3&&p[2]==='status')return(staff&&['open','pending','closed'].includes(op.v))||(t.uid===A&&op.v==='closed')?null:'denied';
  if(p.length===3&&p[2]==='as')return staff&&op.v===A?null:'staff only';return'denied'}
 return'denied'}

function authorize(c,op){
 if(op.c==='users')return rUsers(c,op);
 if(op.c==='srv')return rSrv(c,op);
 if(op.c==='dm')return rDmReal(c,op);
 if(op.c==='inv')return rInv(c,op);
 if(op.c==='plat')return rPlat(c,op);
 return'unknown collection'}
module.exports={authorize,P,dirty,ID,aur,rankOf,lvl,perms,can,isOwner,above,chPerm,HEX,isObj,str};
