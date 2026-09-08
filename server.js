const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8080);
const ROOT = path.resolve(__dirname);
const FRONTEND = path.join(ROOT, 'INSYNC_OPERATIONS_FINANCE_PURCHASE_CONSUMPTION_AI_ADMIN.html');
const RULES_FILE = path.join(ROOT, 'data', 'admin-rules.json');
const AUDIT_FILE = path.join(ROOT, 'data', 'ai-admin-audit.json');
fs.mkdirSync(path.dirname(RULES_FILE), { recursive: true });

const defaultRules = {
  materialReceiptInvoiceMandatory: false,
  consumptionCannotExceedRequested: true,
  purchaseRequestApprovalRole: 'Finance HOD',
  indentApprovalRole: 'Store Incharge',
  stockUpdatesAutomaticallyAfterReceipt: true
};
const allowedSettings = new Set(Object.keys(defaultRules));
function readJson(file, fallback){ try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { return fallback; } }
function writeJson(file, value){ fs.writeFileSync(file, JSON.stringify(value,null,2)); }
if(!fs.existsSync(RULES_FILE)) writeJson(RULES_FILE, defaultRules);
if(!fs.existsSync(AUDIT_FILE)) writeJson(AUDIT_FILE, []);

// Production identity boundary: PK Hospitality owns the single Super Admin role.
// Do not put OPENAI_API_KEY or this admin token in the browser.
const ADMIN_TOKEN = process.env.PK_HOSPITALITY_ADMIN_TOKEN || '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-5.6-luna';
const ADMIN_PASSWORD = process.env.PK_HOSPITALITY_ADMIN_PASSWORD || '';
let sessions = new Map();

function json(res, status, body){
  const out = JSON.stringify(body);
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Access-Control-Allow-Origin':'same-origin'});
  res.end(out);
}
function parseBody(req){ return new Promise((resolve,reject)=>{ let b=''; req.on('data',c=>{b+=c; if(b.length>200000) reject(new Error('Payload too large'));}); req.on('end',()=>{ try{resolve(b?JSON.parse(b):{});}catch(e){reject(e);} }); req.on('error',reject); }); }

function cookies(req){ const raw=req.headers.cookie||''; return Object.fromEntries(raw.split(';').map(x=>x.trim().split('=' )).filter(x=>x.length===2).map(([k,v])=>[k,decodeURIComponent(v)])); }
function sessionUser(req){ const c=cookies(req); return sessions.get(c.insync_session)||null; }
function setSession(res,user){ const sid=crypto.randomBytes(32).toString('hex'); sessions.set(sid,user); res.setHeader('Set-Cookie',`insync_session=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`); return sid; }
function clearSession(req,res){ const c=cookies(req); if(c.insync_session)sessions.delete(c.insync_session); res.setHeader('Set-Cookie','insync_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); }
function configuredUsers(){ try{return JSON.parse(process.env.INSYNC_USERS_JSON||'[]');}catch{return [];} }
function same(a,b){a=String(a||'');b=String(b||'');return a.length===b.length && crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));}

function authorized(req){ const u=sessionUser(req); if(u?.role==='Super Admin' && u.name==='PK Hospitality') return true; const token=String(req.headers['x-pk-admin-token']||''); return Boolean(ADMIN_TOKEN && token && same(token,ADMIN_TOKEN)); }
function adminUser(body){ return body && body.user && body.user.role === 'Super Admin' && String(body.user.name||'').trim() === 'PK Hospitality'; }
function audit(entry){ const a=readJson(AUDIT_FILE,[]); a.push({...entry,at:new Date().toISOString()}); writeJson(AUDIT_FILE,a.slice(-500)); }

async function askOpenAI(command, rules){
  if(!OPENAI_API_KEY) throw new Error('OPENAI_API_KEY is not configured on the server.');
  const system = `You are INSYNC Operations Admin Rule Interpreter. You may ONLY propose changes to the whitelisted application rules below. Never generate or execute JavaScript, SQL, shell commands, arbitrary code, credentials, or destructive actions. Normal users must continue using the application manually. Only Super Admin (PK Hospitality) may approve changes. Return strict JSON with keys: summary, changes, requiresConfirmation. Each changes item must have setting, oldValue, newValue. Whitelisted settings: ${JSON.stringify([...allowedSettings])}. Current rules: ${JSON.stringify(rules)}.`;
  const payload = { model: OPENAI_MODEL, input: [{role:'system',content:system},{role:'user',content:command}], max_output_tokens:1200 };
  const r = await fetch('https://api.openai.com/v1/responses', {method:'POST', headers:{'Authorization':`Bearer ${OPENAI_API_KEY}`,'Content-Type':'application/json'}, body:JSON.stringify(payload)});
  if(!r.ok) throw new Error(`OpenAI request failed (${r.status}).`);
  const d=await r.json();
  const text=(d.output||[]).flatMap(x=>x.content||[]).map(x=>x.text||'').join('').trim();
  let parsed; try{ parsed=JSON.parse(text.replace(/^```json\s*|\s*```$/g,'')); }catch{ throw new Error('AI returned an invalid rule proposal.'); }
  parsed.changes=(parsed.changes||[]).filter(c=>allowedSettings.has(c.setting));
  parsed.requiresConfirmation=true;
  return parsed;
}

const server=http.createServer(async (req,res)=>{
  try{
    if(req.method==='OPTIONS'){ res.writeHead(204, {'Access-Control-Allow-Origin':'same-origin','Access-Control-Allow-Headers':'Content-Type,X-PK-Admin-Token'}); return res.end(); }
    if(req.url==='/api/login' && req.method==='POST') {
      const body=await parseBody(req); const name=String(body.name||'').trim(); const password=String(body.password||'');
      let user=null;
      if(name==='PK Hospitality' && ADMIN_PASSWORD && same(password,ADMIN_PASSWORD)) user={name:'PK Hospitality',role:'Super Admin',owner:'PK Hospitality'};
      else { const found=configuredUsers().find(x=>String(x.name||'').trim()===name && same(password,x.password)); if(found) user={name:found.name,role:found.role,owner:found.owner||'PK Hospitality'}; }
      if(!user) return json(res,401,{ok:false,message:'Invalid credentials.'});
      setSession(res,user); return json(res,200,{ok:true,user});
    }
    if(req.url==='/api/me' && req.method==='GET'){ const u=sessionUser(req); return u?json(res,200,{ok:true,user:u}):json(res,401,{ok:false}); }
    if(req.url==='/api/logout' && req.method==='POST'){ clearSession(req,res); return json(res,200,{ok:true}); }
    if(req.url==='/health'){ return json(res,200,{ok:true,service:'INSYNC Live Backend',adminOwner:'PK Hospitality',aiConfigured:Boolean(OPENAI_API_KEY)}); }
    if(req.url==='/api/admin-rules' && req.method==='GET'){
      if(!authorized(req)) return json(res,403,{ok:false,message:'Super Admin authorization required.'});
      return json(res,200,{ok:true,rules:readJson(RULES_FILE,defaultRules)});
    }
    if(req.url==='/api/admin-ai' && req.method==='POST'){
      const body=await parseBody(req);
      const u=sessionUser(req); if(!authorized(req) || !u || u.role!=='Super Admin' || u.name!=='PK Hospitality') return json(res,403,{ok:false,message:'AI Admin is restricted to PK Hospitality Super Admin.'});
      const rules=readJson(RULES_FILE,defaultRules);
      const proposal=await askOpenAI(String(body.command||''),rules);
      proposal.owner='PK Hospitality'; proposal.command=String(body.command||'');
      audit({type:'proposal',owner:'PK Hospitality',command:proposal.command,proposal});
      return json(res,200,{ok:true,...proposal});
    }
    if(req.url==='/api/admin-ai/apply' && req.method==='POST'){
      const body=await parseBody(req);
      const u=sessionUser(req); if(!authorized(req) || !u || u.role!=='Super Admin' || u.name!=='PK Hospitality') return json(res,403,{ok:false,message:'Only PK Hospitality Super Admin can apply AI Admin changes.'});
      const proposal=body.proposal||{}; if(!proposal.requiresConfirmation) return json(res,400,{ok:false,message:'Confirmation is required.'});
      const rules=readJson(RULES_FILE,defaultRules);
      const applied=[];
      for(const c of proposal.changes||[]){
        if(!allowedSettings.has(c.setting)) continue;
        const oldValue=rules[c.setting];
        rules[c.setting]=c.newValue;
        applied.push({setting:c.setting,oldValue,newValue:c.newValue});
      }
      writeJson(RULES_FILE,rules);
      audit({type:'applied',owner:'PK Hospitality',command:proposal.command||'',changes:applied});
      return json(res,200,{ok:true,message:`${applied.length} Admin rule(s) applied by PK Hospitality.`,rules});
    }
    if(req.url==='/api/admin-audit' && req.method==='GET'){
      if(!authorized(req)) return json(res,403,{ok:false,message:'Super Admin authorization required.'});
      return json(res,200,{ok:true,audit:readJson(AUDIT_FILE,[]).slice(-100).reverse()});
    }
    if(req.method==='GET' && (req.url==='/' || req.url.startsWith('/index.html'))){
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}); return fs.createReadStream(FRONTEND).pipe(res);
    }
    json(res,404,{ok:false,message:'Not found'});
  } catch(e){ json(res,500,{ok:false,message:e.message||'Server error'}); }
});
server.listen(PORT,()=>console.log(`INSYNC Live Backend listening on http://localhost:${PORT}`));
