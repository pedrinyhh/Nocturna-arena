'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {WebSocketServer,WebSocket}=require('ws');
const PORT=process.env.PORT||3000,STORE=path.join(__dirname,'accounts.json');
let users={};try{users=JSON.parse(fs.readFileSync(STORE,'utf8'))}catch{}
const sessions=new Map(),rooms=new Map(),attempts=new Map();
const id=()=>crypto.randomBytes(24).toString('hex');
const safeSend=(ws,data)=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(data))};
function persist(){const tmp=STORE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(users),{mode:0o600});fs.renameSync(tmp,STORE)}
function send(res,status,data){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data))}
function user(token){const k=sessions.get(token);return k&&users[k]?{nick:users[k].nick,role:'player'}:null}
function throttle(ip){const now=Date.now(),r=attempts.get(ip)||{n:0,t:now};if(now-r.t>60000){r.n=0;r.t=now}r.n++;attempts.set(ip,r);return r.n>25}
const server=http.createServer(async(req,res)=>{
 const pathname=(req.url||'/').split('?')[0];
 if(pathname==='/healthz'){res.writeHead(200,{'Content-Type':'text/plain'});return res.end('ok')}
 if(pathname.startsWith('/api/')){
  const ip=req.socket.remoteAddress||'';
  if(throttle(ip))return send(res,429,{error:'Muitas tentativas. Aguarde.'});
  let raw='',size=0;for await(const c of req){size+=c.length;if(size>5000)return send(res,413,{error:'Dados grandes demais'});raw+=c}
  let b={};try{b=raw?JSON.parse(raw):{}}catch{return send(res,400,{error:'JSON inválido'})}
  const token=(req.headers.authorization||'').replace(/^Bearer /,'');const route=pathname.slice(5);
  if(route==='me')return user(token)?send(res,200,{user:user(token)}):send(res,401,{error:'Sessão expirada'});
  if(route==='logout'){sessions.delete(token);return send(res,200,{ok:true})}
  if(route!=='register'&&route!=='login')return send(res,404,{error:'Não encontrado'});
  if(req.method!=='POST')return send(res,405,{error:'Método inválido'});
  const nick=String(b.nick||''),pw=String(b.password||''),key=nick.toLowerCase();
  if(!/^[a-zA-Z0-9_]{3,16}$/.test(nick)||pw.length<8||pw.length>128)return send(res,400,{error:'Nick ou senha inválidos'});
  if(route==='register'){
   if(users[key])return send(res,409,{error:'Nick já existe'});
   const salt=crypto.randomBytes(16).toString('hex');users[key]={nick,salt,hash:crypto.scryptSync(pw,salt,64).toString('hex')};persist();
  }else{
   const u=users[key];if(!u)return send(res,401,{error:'Credenciais inválidas'});
   const hash=crypto.scryptSync(pw,u.salt,64),saved=Buffer.from(u.hash,'hex');
   if(hash.length!==saved.length||!crypto.timingSafeEqual(hash,saved))return send(res,401,{error:'Credenciais inválidas'});
  }
  const t=id();sessions.set(t,key);return send(res,200,{token:t,user:{nick:users[key].nick,role:'player'}});
 }
 if(pathname!=='/'&&pathname!=='/index.html')return send(res,404,{error:'Não encontrado'});
 fs.readFile(path.join(__dirname,'public','index.html'),(e,data)=>{
  if(e)return send(res,404,{error:'Arquivo ausente'});
  res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self' https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"});res.end(data);
 });
});
const wss=new WebSocketServer({server,path:'/ws',maxPayload:4096});
function broadcast(room){const peers=[...room.members].map(p=>({id:p.id,data:p.data}));for(const p of room.members)safeSend(p,{type:'peers',peers})}
function listRooms(){return [...rooms.entries()].filter(([,r])=>r.members.size<2).slice(0,100).map(([code,r])=>({code,name:r.name,players:r.members.size}))}
function leave(ws){if(!ws.room)return;const room=rooms.get(ws.room);if(room){room.members.delete(ws);if(!room.members.size)rooms.delete(ws.room);else broadcast(room)}ws.room=null}
function number(v,min,max){const n=Number(v);return Number.isFinite(n)?Math.max(min,Math.min(max,n)):undefined}
wss.on('connection',ws=>{
 ws.alive=true;ws.on('pong',()=>{ws.alive=true});ws.id=id();ws.data={};ws.last=0;ws.messages=0;ws.window=Date.now();
 ws.on('message',raw=>{
  if(raw.length>4000)return ws.close(1009,'Mensagem grande');
  const now=Date.now();if(now-ws.window>1000){ws.window=now;ws.messages=0}if(++ws.messages>55)return ws.close(1008,'Muitas mensagens');
  let m;try{m=JSON.parse(raw)}catch{return}if(!m||typeof m!=='object')return;
  if(m.type==='list_rooms'){safeSend(ws,{type:'rooms',rooms:listRooms()});return}
  if(m.type==='join'){
   if(ws.room)return;
   const code=String(m.code||'').trim().toLowerCase();if(!/^[a-z0-9_-]{3,20}$/.test(code))return safeSend(ws,{type:'error',error:'Código inválido'});
   let room=rooms.get(code);if(!room){room={name:String(m.name||code).replace(/[<>]/g,'').slice(0,40)||code,members:new Set()};rooms.set(code,room)}
   if(room.members.size>=2)return safeSend(ws,{type:'error',error:'Sala cheia'});
   ws.room=code;room.members.add(ws);ws.data={t0:now,hp:100,x:-5,y:0,z:0};
   safeSend(ws,{type:'joined',id:ws.id,slot:room.members.size-1});broadcast(room);
   if(room.members.size===2){for(const p of room.members)safeSend(p,{type:'match_intro',duration:7000})}
   return;
  }
  if(m.type==='state'&&ws.room){
   if(now-ws.last<30)return;const elapsed=Math.max(.03,(now-ws.last)/1000);ws.last=now;
   const d=m.data;if(!d||typeof d!=='object'||Array.isArray(d))return;
   const out={};for(const key of ['x','y','z','ry','hp','mx','dead','bl','pc','sk','n','wv','sl','t0']){
    const v=number(d[key],-1000,1000);if(v!==undefined)out[key]=v;
   }
   for(const key of ['x','y','z'])if(out[key]!==undefined&&ws.data[key]!==undefined){
    if(Math.abs(out[key]-ws.data[key])>Math.max(3,elapsed*40))return;
   }
   out.nm=String(d.nm||'').slice(0,16);
   // Compatibilidade V2: o cliente ainda calcula dano. O servidor limita, mas NÃO valida acertos autoritativamente.
   if(d.h&&typeof d.h==='object')out.h={to:String(d.h.to||'').slice(0,48),dmg:number(d.h.dmg,0,18)||0,kb:number(d.h.kb,0,26)||0};
   for(const key of ['wd','sp'])if(Array.isArray(d[key]))out[key]=d[key].slice(0,5).map(x=>number(x,-1000,1000)||0);
   ws.data={...ws.data,...out};const room=rooms.get(ws.room);
   if(room)for(const peer of room.members)if(peer!==ws)safeSend(peer,{type:'state',id:ws.id,data:ws.data});
  }
 });
 ws.on('close',()=>leave(ws));ws.on('error',()=>leave(ws));
});
setInterval(()=>{for(const c of wss.clients){if(!c.alive){c.terminate();continue}c.alive=false;try{c.ping()}catch{}}const now=Date.now();for(const [ip,r] of attempts)if(now-r.t>120000)attempts.delete(ip)},25000).unref();
server.listen(PORT,()=>console.log('NOCTURNA ARENA V2: http://localhost:'+PORT));
