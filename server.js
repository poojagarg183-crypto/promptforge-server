require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const https   = require("https");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3005;

// ─────────────────────────────────────────────────────────────
// JWT
// ─────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.warn("⚠️  JWT_SECRET not set — set it in Railway Variables");
  return crypto.randomBytes(32).toString("hex");
})();

const b64u    = b => Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
const signJWT = p => {
  const h = b64u(JSON.stringify({alg:"HS256",typ:"JWT"}));
  const b = b64u(JSON.stringify({...p, iat:Math.floor(Date.now()/1000)}));
  const s = b64u(crypto.createHmac("sha256",JWT_SECRET).update(`${h}.${b}`).digest());
  return `${h}.${b}.${s}`;
};
const verifyJWT = token => {
  try {
    const [h,b,s] = token.split(".");
    if (s !== b64u(crypto.createHmac("sha256",JWT_SECRET).update(`${h}.${b}`).digest())) return null;
    const p = JSON.parse(Buffer.from(b,"base64").toString());
    if (p.iat && Date.now()/1000 - p.iat > 30*86400) return null;
    return p;
  } catch { return null; }
};
const requireAuth = (req,res,next) => {
  const t = (req.headers.authorization||"").slice(7);
  const p = t && verifyJWT(t);
  if (!p) return res.status(401).json({error:"Unauthorized"});
  req.user = p; next();
};

// ─────────────────────────────────────────────────────────────
// FILE-BASED STORES
// ─────────────────────────────────────────────────────────────
// DATA_DIR: uses /app/data when DATA_DIR env var set (Railway volume), else local __dirname
const DATA_DIR     = process.env.DATA_DIR || __dirname;
const USERS_FILE   = path.join(DATA_DIR, "users.json");
const PENDING_FILE = path.join(DATA_DIR, "pending.json");

// Ensure data directory exists (important when volume is mounted)
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const loadUsers   = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE,"utf8")); } catch { return {}; } };
const saveUsers   = u  => fs.writeFileSync(USERS_FILE, JSON.stringify(u,null,2));
const loadPending = () => { try { return JSON.parse(fs.readFileSync(PENDING_FILE,"utf8")); } catch { return {}; } };
const savePending = p  => fs.writeFileSync(PENDING_FILE, JSON.stringify(p,null,2));
const hashPw      = (pw,salt) => crypto.pbkdf2Sync(pw,salt,100000,64,"sha512").toString("hex");

// ─────────────────────────────────────────────────────────────
// EMAIL — uses Resend HTTP API (no SMTP, works on Railway)
// Set RESEND_API_KEY in Railway Variables to enable real emails.
// Without it: codes are shown in UI yellow box + server logs.
// ─────────────────────────────────────────────────────────────
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM     = process.env.EMAIL_FROM || "PromptForge <onboarding@resend.dev>";

async function sendVerificationEmail(email, code) {
  if (!RESEND_API_KEY) {
    console.log(`\n📧 [DEV] Verification code for ${email}: ${code}\n`);
    return { dev: true };
  }

  const body = JSON.stringify({
    from:    EMAIL_FROM,
    to:      [email],
    subject: `${code} — your PromptForge verification code`,
    text:    `Your PromptForge verification code is: ${code}\n\nExpires in 15 minutes.\nIf you didn't request this, ignore this email.`,
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: "api.resend.com",
      path:     "/emails",
      method:   "POST",
      headers:  {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type":  "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    }, res => {
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          console.log(`📧 Email sent to ${email}`);
          resolve({ sent: true });
        } else {
          console.error(`📧 Resend error ${res.statusCode}:`, data);
          reject(new Error(`Email API error: ${data}`));
        }
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────
// AI PROVIDERS
// ─────────────────────────────────────────────────────────────
const PROVIDER           = process.env.PROVIDER           || "groq";
const GROQ_API_KEY       = process.env.GROQ_API_KEY       || "";
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const GEMINI_API_KEY     = process.env.GEMINI_API_KEY     || "";

const PROVIDERS = {
  groq: {
    hostname:"api.groq.com", path:"/openai/v1/chat/completions", model:"llama-3.3-70b-versatile",
    authHeader:()=>`Bearer ${GROQ_API_KEY}`,
    buildBody:(p,t)=>JSON.stringify({model:"llama-3.3-70b-versatile",messages:[{role:"user",content:p}],max_tokens:t,temperature:0.7}),
    extractText:d=>d?.choices?.[0]?.message?.content,
  },
  openrouter: {
    hostname:"openrouter.ai", path:"/api/v1/chat/completions", model:"meta-llama/llama-3.3-70b-instruct:free",
    authHeader:()=>`Bearer ${OPENROUTER_API_KEY}`,
    buildBody:(p,t)=>JSON.stringify({model:"meta-llama/llama-3.3-70b-instruct:free",messages:[{role:"user",content:p}],max_tokens:t}),
    extractText:d=>d?.choices?.[0]?.message?.content,
  },
  gemini: {
    hostname:"generativelanguage.googleapis.com",
    path:`/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
    model:"gemini-2.0-flash", authHeader:()=>null,
    buildBody:(p,t)=>JSON.stringify({contents:[{parts:[{text:p}]}],generationConfig:{temperature:0.7,maxOutputTokens:t}}),
    extractText:d=>d?.candidates?.[0]?.content?.parts?.[0]?.text,
  },
};

// ─────────────────────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────────────────────
const IS_PROD         = process.env.NODE_ENV === "production";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!IS_PROD && (origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:")))
      return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes("*")) return cb(null, true);
    console.warn(`CORS blocked: ${origin}`);
    cb(new Error("Not allowed by CORS"));
  },
  credentials: true,
}));
app.use(express.json({ limit:"2mb" }));

// ─────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────

app.post("/auth/send-code", async (req, res) => {
  const { username, email, password } = req.body || {};
  console.log("[send-code]", { username, email, passwordLen: password?.length });

  if (!username || !email || !password)
    return res.status(400).json({ error: "username, email and password are all required" });
  if (username.trim().length < 3)
    return res.status(400).json({ error: "username must be 3+ characters" });
  if (!/^[a-zA-Z0-9_-]+$/.test(username.trim()))
    return res.status(400).json({ error: "username: letters, numbers, _ or - only" });
  if (!email.includes("@"))
    return res.status(400).json({ error: "enter a valid email address" });
  if (password.length < 6)
    return res.status(400).json({ error: "password must be 6+ characters" });

  const users = loadUsers();
  if (users[username.trim().toLowerCase()])
    return res.status(409).json({ error: "Username already taken" });
  if (Object.values(users).find(u => u.email === email.trim().toLowerCase()))
    return res.status(409).json({ error: "Email already registered — sign in instead" });

  const code      = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 15 * 60 * 1000;
  const pending   = loadPending();
  pending[email.trim().toLowerCase()] = { code, expiresAt, username: username.trim(), password };
  savePending(pending);

  try {
    const result = await sendVerificationEmail(email.trim(), code);
    res.json({ sent: true, dev: (result?.dev || !RESEND_API_KEY) ? code : undefined });
  } catch (e) {
    console.error("Email failed:", e.message);
    // Still let them in — show code in UI
    res.json({ sent: true, dev: code, warning: "Email failed — use this code" });
  }
});

app.post("/auth/verify-register", (req, res) => {
  const { email, code } = req.body || {};
  console.log("[verify-register]", { email, code });

  if (!email || !code)
    return res.status(400).json({ error: "email and code required" });

  const pending = loadPending();
  const record  = pending[email.trim().toLowerCase()];

  if (!record)
    return res.status(400).json({ error: "No pending verification — register again" });
  if (Date.now() > record.expiresAt) {
    delete pending[email.trim().toLowerCase()]; savePending(pending);
    return res.status(400).json({ error: "Code expired — register again" });
  }
  if (record.code !== code.trim())
    return res.status(400).json({ error: "Wrong code — check your email" });

  const users = loadUsers();
  const key   = record.username.toLowerCase();
  if (users[key]) {
    delete pending[email.trim().toLowerCase()]; savePending(pending);
    return res.status(409).json({ error: "Username taken" });
  }

  const salt = crypto.randomBytes(32).toString("hex");
  const hash = hashPw(record.password, salt);
  users[key] = { username:record.username, email:email.trim().toLowerCase(), hash, salt, createdAt:new Date().toISOString(), verified:true };
  saveUsers(users);
  delete pending[email.trim().toLowerCase()]; savePending(pending);

  const token = signJWT({ username:record.username, sub:key });
  console.log(`✅ Registered: ${record.username}`);
  res.json({ token, user:{ username:record.username, email:email.trim().toLowerCase() } });
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  console.log("[login]", { username, passwordLen: password?.length });

  if (!username || !password)
    return res.status(400).json({ error: "username and password required" });

  const users  = loadUsers();
  const record = users[username.trim().toLowerCase()];
  if (!record || hashPw(password, record.salt) !== record.hash)
    return res.status(401).json({ error: "Invalid username or password" });

  const token = signJWT({ username:record.username, sub:username.trim().toLowerCase() });
  console.log(`✅ Login: ${record.username}`);
  res.json({ token, user:{ username:record.username, email:record.email } });
});

app.get("/auth/me", requireAuth, (req, res) => {
  res.json({ user:{ username:req.user.username } });
});

// ─────────────────────────────────────────────────────────────
// AI PROXY
// ─────────────────────────────────────────────────────────────
app.get("/", (_, res) => res.json({ status:"PromptForge API ✅", provider:PROVIDER }));

app.post("/api/gemini", (req, res) => {
  const { prompt, maxTokens = 800 } = req.body || {};
  if (!prompt) return res.status(400).json({ error:"prompt required" });

  const p    = PROVIDERS[PROVIDER];
  const body = p.buildBody(prompt, maxTokens);
  const auth = p.authHeader();
  const hdrs = { "Content-Type":"application/json", "Content-Length":Buffer.byteLength(body) };
  if (auth) hdrs["Authorization"] = auth;
  if (PROVIDER === "openrouter") { hdrs["HTTP-Referer"]="https://promptforge.app"; hdrs["X-Title"]="PromptForge"; }

  const apiReq = https.request({ hostname:p.hostname, path:p.path, method:"POST", headers:hdrs }, apiRes => {
    let data = "";
    apiRes.on("data", c => { data += c; });
    apiRes.on("end", () => {
      let parsed;
      try { parsed = JSON.parse(data); } catch { return res.status(500).json({ error:"Bad JSON from provider" }); }
      if (apiRes.statusCode !== 200)
        return res.status(apiRes.statusCode).json({ error:`${PROVIDER}: ${parsed?.error?.message||JSON.stringify(parsed)}` });
      const text = p.extractText(parsed);
      if (!text) return res.status(500).json({ error:"Empty provider response" });
      res.json({ text });
    });
  });
  apiReq.on("error", e => res.status(500).json({ error:"Network: "+e.message }));
  apiReq.write(body); apiReq.end();
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  PromptForge server  →  http://localhost:${PORT}`);
  console.log(`    AI Provider : ${PROVIDER}`);
  console.log(`    Email       : ${RESEND_API_KEY ? "Resend API ready ✅" : "DEV MODE — codes shown in UI"}`);
  console.log(`    CORS        : ${IS_PROD ? (ALLOWED_ORIGINS.join(", ")||"⚠️ set ALLOWED_ORIGINS") : "all localhost"}\n`);
});
