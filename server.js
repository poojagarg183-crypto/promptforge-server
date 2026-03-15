require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const https     = require("https");
const crypto    = require("crypto");
const fs        = require("fs");
const path      = require("path");
const nodemailer= require("nodemailer");

const app  = express();
const PORT = process.env.PORT || 3005;

// ─────────────────────────────────────────────────────────────
// JWT  (zero deps, HS256)
// ─────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.warn("⚠️  JWT_SECRET not set — tokens invalidate on restart. Set it in .env");
  return crypto.randomBytes(32).toString("hex");
})();

const b64u = b => Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
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
const USERS_FILE   = path.join(__dirname, "users.json");
const PENDING_FILE = path.join(__dirname, "pending.json");

const loadUsers   = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE,"utf8")); } catch { return {}; } };
const saveUsers   = u  => fs.writeFileSync(USERS_FILE, JSON.stringify(u,null,2));
const loadPending = () => { try { return JSON.parse(fs.readFileSync(PENDING_FILE,"utf8")); } catch { return {}; } };
const savePending = p  => fs.writeFileSync(PENDING_FILE, JSON.stringify(p,null,2));
const hashPw      = (pw,salt) => crypto.pbkdf2Sync(pw,salt,100000,64,"sha512").toString("hex");

// ─────────────────────────────────────────────────────────────
// EMAIL
// ─────────────────────────────────────────────────────────────
let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host:   process.env.SMTP_HOST,
    port:   Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  mailer.verify(err => {
    if (err) console.warn("⚠️  SMTP not ready:", err.message);
    else     console.log("✅ Email (SMTP) ready");
  });
} else {
  console.warn("⚠️  SMTP not configured — codes will be shown in UI and server console");
}

async function sendVerificationEmail(email, code) {
  const text = `Your PromptForge verification code is: ${code}\n\nExpires in 15 minutes.`;
  if (mailer) {
    await mailer.sendMail({
      from:    process.env.EMAIL_FROM || "PromptForge <noreply@example.com>",
      to:      email,
      subject: `${code} — PromptForge verification code`,
      text,
    });
    console.log(`📧 Verification email sent to ${email}`);
  } else {
    console.log(`\n📧 [DEV] Code for ${email}: ${code}\n`);
  }
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
// CORS — allow all localhost in dev, strict in production
// ─────────────────────────────────────────────────────────────
const IS_PROD        = process.env.NODE_ENV === "production";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS||"").split(",").map(s=>s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!IS_PROD && (origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:"))) {
      return cb(null, true);
    }
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

// POST /auth/send-code
app.post("/auth/send-code", async (req, res) => {
  const { username, email, password } = req.body || {};

  // Log what we received to help debug
  console.log("[send-code] received:", { username, email, passwordLen: password?.length });

  if (!username || !email || !password)
    return res.status(400).json({ error: "username, email and password are all required" });
  if (username.trim().length < 3)
    return res.status(400).json({ error: "username must be 3+ characters" });
  if (!/^[a-zA-Z0-9_-]+$/.test(username.trim()))
    return res.status(400).json({ error: "username can only contain letters, numbers, _ or -" });
  if (!email.includes("@"))
    return res.status(400).json({ error: "enter a valid email address" });
  if (password.length < 6)
    return res.status(400).json({ error: "password must be 6+ characters" });

  const users = loadUsers();
  if (users[username.trim().toLowerCase()])
    return res.status(409).json({ error: "Username already taken — try another" });
  if (Object.values(users).find(u => u.email === email.trim().toLowerCase()))
    return res.status(409).json({ error: "Email already registered — sign in instead" });

  const code      = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 15 * 60 * 1000;

  // Save to file so it survives server restarts
  const pending = loadPending();
  pending[email.trim().toLowerCase()] = { code, expiresAt, username: username.trim(), password };
  savePending(pending);

  try {
    await sendVerificationEmail(email.trim(), code);
    // If no SMTP, return code in response so UI can show it
    res.json({ sent: true, dev: !mailer ? code : undefined });
  } catch (e) {
    console.error("Email send failed:", e.message);
    // Still return the code in dev mode even if email failed
    res.json({ sent: true, dev: code, warning: "Email failed — use this code: " + code });
  }
});

// POST /auth/verify-register
app.post("/auth/verify-register", (req, res) => {
  const { email, code } = req.body || {};
  console.log("[verify-register] received:", { email, code });

  if (!email || !code)
    return res.status(400).json({ error: "email and code are required" });

  const pending = loadPending();
  const record  = pending[email.trim().toLowerCase()];

  if (!record)
    return res.status(400).json({ error: "No pending verification for this email — register again" });
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
  users[key] = {
    username:  record.username,
    email:     email.trim().toLowerCase(),
    hash, salt,
    createdAt: new Date().toISOString(),
    verified:  true,
  };
  saveUsers(users);
  delete pending[email.trim().toLowerCase()]; savePending(pending);

  const token = signJWT({ username: record.username, sub: key });
  console.log(`✅ Registered + verified: ${record.username}`);
  res.json({ token, user: { username: record.username, email: email.trim().toLowerCase() } });
});

// POST /auth/login
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  console.log("[login] received:", { username, passwordLen: password?.length });

  if (!username || !password)
    return res.status(400).json({ error: "username and password required" });

  const users  = loadUsers();
  const record = users[username.trim().toLowerCase()];
  if (!record)
    return res.status(401).json({ error: "Invalid username or password" });
  if (hashPw(password, record.salt) !== record.hash)
    return res.status(401).json({ error: "Invalid username or password" });

  const token = signJWT({ username: record.username, sub: username.trim().toLowerCase() });
  console.log(`✅ Login: ${record.username}`);
  res.json({ token, user: { username: record.username, email: record.email } });
});

// GET /auth/me
app.get("/auth/me", requireAuth, (req, res) => {
  res.json({ user: { username: req.user.username } });
});

// ─────────────────────────────────────────────────────────────
// AI PROXY
// ─────────────────────────────────────────────────────────────
app.get("/", (_, res) => res.json({
  status:   "PromptForge API ✅",
  provider: PROVIDER,
  model:    PROVIDERS[PROVIDER]?.model,
  auth:     "JWT + email verification",
}));

app.post("/api/gemini", (req, res) => {
  const { prompt, maxTokens = 800 } = req.body || {};
  if (!prompt) return res.status(400).json({ error: "prompt required" });
  console.log(`[AI] ${PROVIDER} — ${prompt.length} chars`);

  const p    = PROVIDERS[PROVIDER];
  const body = p.buildBody(prompt, maxTokens);
  const auth = p.authHeader();
  const hdrs = { "Content-Type":"application/json", "Content-Length":Buffer.byteLength(body) };
  if (auth) hdrs["Authorization"] = auth;
  if (PROVIDER === "openrouter") {
    hdrs["HTTP-Referer"] = IS_PROD ? "https://promptforge.app" : "http://localhost:3000";
    hdrs["X-Title"]      = "PromptForge";
  }

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
      console.log(`[AI] OK — ${text.length} chars`);
      res.json({ text });
    });
  });
  apiReq.on("error", e => res.status(500).json({ error:"Network: "+e.message }));
  apiReq.write(body);
  apiReq.end();
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  PromptForge server  →  http://localhost:${PORT}`);
  console.log(`    AI Provider : ${PROVIDER}  (${PROVIDERS[PROVIDER]?.model||"unknown"})`);
  console.log(`    Auth        : JWT HS256, 30-day tokens`);
  console.log(`    Email       : ${mailer ? "SMTP configured" : "DEV MODE — codes shown in UI + console"}`);
  console.log(`    CORS        : ${IS_PROD ? (ALLOWED_ORIGINS.join(", ")||"⚠️  set ALLOWED_ORIGINS") : "all localhost (dev mode)"}`);
  console.log(`    Users file  : ${USERS_FILE}`);
  console.log(`    Pending file: ${PENDING_FILE}`);
  console.log(`\n    POST /auth/send-code        { username, email, password }`);
  console.log(`    POST /auth/verify-register  { email, code }`);
  console.log(`    POST /auth/login            { username, password }`);
  console.log(`    GET  /auth/me`);
  console.log(`    POST /api/gemini            { prompt, maxTokens }\n`);
});
